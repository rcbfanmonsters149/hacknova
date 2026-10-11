"""Demo seeding script for PromptShield X.
Initializes SQLite database with default security policies, initial evaluations,
and standard demonstration scenarios.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.storage import init_db, get_connection
from backend.app.policy_engine import DEFAULT_POLICIES
from backend.scripts.evaluate import run_evaluation

def seed_policies():
    conn = get_connection()
    cursor = conn.cursor()
    for p in DEFAULT_POLICIES:
        cursor.execute("""
        INSERT OR REPLACE INTO policies (id, version, name, category, rule_id, action, priority, is_hard_rule, enabled, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            p["id"], p["version"], p["name"], p["category"], p["rule_id"],
            p["action"], p["priority"], 1 if p["is_hard_rule"] else 0,
            1 if p["enabled"] else 0, p["description"]
        ))
    conn.commit()
    conn.close()
    print("Seeded default security policies.")

def main():
    print("Initializing database...")
    init_db()
    seed_policies()
    print("Running initial evaluation to generate real benchmarks...")
    run_evaluation()
    print("Seed complete!")

if __name__ == "__main__":
    main()
