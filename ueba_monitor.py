
import json
import time
from datetime import datetime
from collections import defaultdict

# In-memory storage for user and entity behavior profiles
# In a real implementation, you would use a database for persistence
user_profiles = defaultdict(lambda: {
    'login_times': [],
    'usual_login_hours': set(),
    'accessed_files': set()
})

def profile_user_activity(alert):
    """Profiles user activity based on incoming alerts."""
    user_id = alert.get('user_id')
    if not user_id:
        return

    # Profile login times
    if alert.get('event_type') == 'login':
        login_time = datetime.fromisoformat(alert['timestamp'])
        user_profiles[user_id]['login_times'].append(login_time)
        user_profiles[user_id]['usual_login_hours'].add(login_time.hour)

    # Profile file access
    if alert.get('event_type') == 'file_access':
        file_path = alert.get('file_path')
        if file_path:
            user_profiles[user_id]['accessed_files'].add(file_path)

def detect_anomalies(alert):
    """Detects anomalies based on user behavior profiles."""
    user_id = alert.get('user_id')
    if not user_id:
        return

    # Anomaly: Unusual login time
    if alert.get('event_type') == 'login':
        login_time = datetime.fromisoformat(alert['timestamp'])
        if login_time.hour not in user_profiles[user_id]['usual_login_hours']:
            print(f"Anomaly detected: User {user_id} logged in at an unusual time ({login_time.hour}:00)")

    # Anomaly: Access to a new sensitive file
    if alert.get('event_type') == 'file_access':
        file_path = alert.get('file_path')
        if file_path and file_path.startswith('/sensitive/') and file_path not in user_profiles[user_id]['accessed_files']:
            print(f"Anomaly detected: User {user_id} accessed a new sensitive file: {file_path}")

def main():
    """Main function to process alerts and detect anomalies."""
    # This is a placeholder for a real-time alert processing loop
    # In a real implementation, this would be integrated with the aggregator
    pass

if __name__ == '__main__':
    main()
