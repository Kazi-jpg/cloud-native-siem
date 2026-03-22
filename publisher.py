import json
from google.cloud import pubsub_v1

PROJECT_ID = "cloud-native-siem"
TOPIC_ID = "siem-events"

publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)


def publish_event(event: dict) -> str:
    message_bytes = json.dumps(event).encode("utf-8")
    future = publisher.publish(topic_path, message_bytes)
    message_id = future.result()
    return message_id