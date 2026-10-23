import ipaddress
import logging
import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SecurityRule

logger = logging.getLogger("soar")

# Reserve a priority range for SOAR rules (lower number = evaluated first).
PRIORITY_MIN, PRIORITY_MAX = 100, 499


def _rule_name(ip: str) -> str:
    return "soar-block-" + ip.replace(".", "-").replace(":", "-")


class AzureNsgBlocker:
    def __init__(self):
        self.rg = os.environ["AZURE_RESOURCE_GROUP"]
        self.nsg = os.environ["AZURE_NSG_NAME"]
        self.client = NetworkManagementClient(
            DefaultAzureCredential(), os.environ["AZURE_SUBSCRIPTION_ID"]
        )

    def _rules(self):
        return list(self.client.security_rules.list(self.rg, self.nsg))

    def block(self, ip: str) -> dict:
        # Defense in depth: never write a rule for a private/reserved address.
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("refusing to block a non-public IP")

        name = _rule_name(ip)
        rules = self._rules()
        if any(r.name == name for r in rules):
            return {"executed": False, "backend": "azure_nsg", "rule": name,
                    "detail": "already blocked"}

        used = {r.priority for r in rules}
        priority = next(
            (p for p in range(PRIORITY_MIN, PRIORITY_MAX + 1) if p not in used), None
        )
        if priority is None:
            raise RuntimeError("no free priority left in the SOAR range")

        rule = SecurityRule(
            description="Auto-blocked by SOAR app",
            protocol="*",
            source_address_prefix=ip,
            source_port_range="*",
            destination_address_prefix="*",
            destination_port_range="*",
            access="Deny",
            direction="Inbound",
            priority=priority,
        )
        self.client.security_rules.begin_create_or_update(
            self.rg, self.nsg, name, rule
        ).result()
        logger.info("Azure NSG rule %s created (priority %s)", name, priority)
        return {"executed": True, "backend": "azure_nsg", "rule": name,
                "priority": priority}

    def unblock(self, ip: str) -> dict:
        name = _rule_name(ip)
        if not any(r.name == name for r in self._rules()):
            return {"executed": False, "backend": "azure_nsg", "rule": name,
                    "detail": "no such rule"}
        self.client.security_rules.begin_delete(self.rg, self.nsg, name).result()
        logger.info("Azure NSG rule %s deleted", name)
        return {"executed": True, "backend": "azure_nsg", "rule": name}