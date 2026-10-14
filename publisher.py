import json
import os
from google.cloud import pubsub_v1

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "cloud-native-siem")
TOPIC_ID = os.getenv("PUBSUB_TOPIC_ID", "siem-events")

publisher = None


def publish_event(event: dict) -> str:
    global publisher
    if publisher is None:
        publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)
    message_bytes = json.dumps(event).encode("utf-8")
    future = publisher.publish(topic_path, message_bytes)
    message_id = future.result()
    return message_id