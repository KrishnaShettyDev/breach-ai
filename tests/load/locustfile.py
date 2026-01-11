"""
BREACH.AI - Load Testing
=========================
Locust load test scenarios for the API.

Run with:
    locust -f tests/load/locustfile.py --host=http://localhost:8000
"""

import random
from locust import HttpUser, task, between


class BreachAPIUser(HttpUser):
    """
    Simulated user for load testing BREACH.AI API.

    Requires authentication headers to be set.
    In real testing, you'd use actual API keys or mock auth.
    """

    wait_time = between(1, 3)

    def on_start(self):
        """Set up authentication headers."""
        # In real testing, use actual API key
        self.headers = {
            "Authorization": "Bearer test_token",
            "Content-Type": "application/json"
        }

    @task(10)
    def health_check(self):
        """Check API health."""
        self.client.get("/health")

    @task(5)
    def deep_health_check(self):
        """Check deep health endpoint."""
        self.client.get("/health/deep")

    @task(3)
    def list_scans(self):
        """List scans with pagination."""
        page = random.randint(1, 10)
        per_page = random.choice([10, 20, 50])
        self.client.get(
            "/api/v1/scans",
            params={"page": page, "per_page": per_page},
            headers=self.headers
        )

    @task(2)
    def get_stats(self):
        """Get scan statistics."""
        self.client.get(
            "/api/v1/scans/stats",
            headers=self.headers
        )

    @task(1)
    def create_scan(self):
        """Create a new scan (rate limited)."""
        targets = [
            "https://example.com",
            "https://test.example.com",
            "https://api.example.com",
        ]
        self.client.post(
            "/api/v1/scans",
            json={
                "target_url": random.choice(targets),
                "mode": random.choice(["quick", "normal", "deep"])
            },
            headers=self.headers
        )

    @task(2)
    def list_targets(self):
        """List targets."""
        self.client.get(
            "/api/v1/targets",
            headers=self.headers
        )


class AnonymousUser(HttpUser):
    """
    Unauthenticated user for testing public endpoints.
    """

    wait_time = between(1, 5)

    @task(10)
    def health_check(self):
        """Check basic health."""
        self.client.get("/health")

    @task(5)
    def root_endpoint(self):
        """Check root endpoint."""
        self.client.get("/")

    @task(3)
    def api_docs(self):
        """Access API documentation."""
        self.client.get("/docs")


class RateLimitTestUser(HttpUser):
    """
    User for testing rate limiting behavior.
    """

    wait_time = between(0.1, 0.5)  # Fast requests to trigger rate limits

    def on_start(self):
        self.headers = {
            "Authorization": "Bearer test_token",
            "Content-Type": "application/json"
        }

    @task
    def rapid_scan_creation(self):
        """Rapidly create scans to trigger rate limits."""
        with self.client.post(
            "/api/v1/scans",
            json={
                "target_url": "https://example.com",
                "mode": "quick"
            },
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 429:
                response.success()  # Rate limit is expected
            elif response.status_code == 201:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
