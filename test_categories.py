import os
import unittest

os.environ.setdefault("CLOUDFLARE_ZONE_ID", "zone")
os.environ.setdefault("CLOUDFLARE_EMAIL", "user@example.com")
os.environ.setdefault("CLOUDFLARE_API_KEY", "cloudflare-key")
os.environ.setdefault("ABUSEIPDB_API_KEY", "abuse-key")

import main


def event(**overrides):
    data = {
        "source": "firewallmanaged",
        "clientRequestHTTPMethodName": "GET",
        "clientRequestPath": "/",
        "clientRequestQuery": "",
        "userAgent": "Mozilla/5.0",
    }
    data.update(overrides)
    return data


class GetCategoriesTest(unittest.TestCase):
    def test_managed_waf_block_is_web_app_attack(self):
        self.assertEqual(main.get_categories(event(source="firewallmanaged")), "21")

    def test_sql_injection_adds_specific_category(self):
        categories = main.get_categories(
            event(clientRequestQuery="id=1 UNION SELECT password FROM users")
        )

        self.assertEqual(categories, "16,21")

    def test_bot_source_is_bad_web_bot(self):
        self.assertEqual(main.get_categories(event(source="botmanagement")), "19")

    def test_bot_user_agent_is_bad_web_bot(self):
        self.assertEqual(
            main.get_categories(event(source="securitylevel", userAgent="sqlmap/1.8")),
            "19",
        )

    def test_web_probe_path_is_web_app_attack(self):
        self.assertEqual(main.get_categories(event(clientRequestPath="/.env")), "21")

    def test_wordpress_rest_probe_is_web_app_attack(self):
        categories = main.get_categories(
            event(
                clientRequestPath="/wordpress/wp-json/",
                clientRequestQuery="?rest_route=/",
            )
        )

        self.assertEqual(categories, "21")

    def test_wordpress_rest_route_probe_is_web_app_attack(self):
        categories = main.get_categories(
            event(
                source="firewallCustom",
                clientRequestPath="/blog/",
                clientRequestQuery="?rest_route=/",
            )
        )

        self.assertEqual(categories, "21")

    def test_wordpress_config_backup_probe_is_web_app_attack(self):
        self.assertEqual(
            main.get_categories(
                event(source="firewallCustom", clientRequestPath="/wp-config.php.bak")
            ),
            "21",
        )

    def test_admin_route_probe_is_web_app_attack(self):
        self.assertEqual(
            main.get_categories(
                event(source="firewallCustom", clientRequestPath="/settings")
            ),
            "21",
        )

    def test_known_crawler_probe_is_not_bad_web_bot_by_name_only(self):
        categories = main.get_categories(
            event(
                source="firewallCustom",
                clientRequestPath="/wp-config.php",
                userAgent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            )
        )

        self.assertEqual(categories, "21")

    def test_post_to_login_path_is_brute_force_and_web_app_attack(self):
        categories = main.get_categories(
            event(clientRequestHTTPMethodName="POST", clientRequestPath="/wp-login.php")
        )

        self.assertEqual(categories, "18,21")

    def test_l7ddos_source_is_ddos_attack(self):
        self.assertEqual(main.get_categories(event(source="l7ddos")), "4")

    def test_unknown_event_falls_back_to_generic_hacking(self):
        self.assertEqual(main.get_categories(event(source="securitylevel")), "15")


if __name__ == "__main__":
    unittest.main()
