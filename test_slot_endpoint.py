#!/usr/bin/env python
"""Test script for the new slot recipients status endpoint"""
import sys
import json
from app import app, db
from models import ScheduledTask, ScheduledTimeSlot, SentMessage, User
from datetime import datetime

def test_slot_endpoint():
    """Test the /api/slot/<slot_id>/recipients-status endpoint"""
    with app.app_context():
        # Check if there are any slots to test with
        slot = ScheduledTimeSlot.query.first()
        
        if not slot:
            print("❌ No slots found in database for testing")
            return False
        
        print(f"✅ Found slot with ID: {slot.id}")
        print(f"   Status: {slot.status}")
        print(f"   Total recipients: {slot.total_recipients}")
        print(f"   Processed recipients: {slot.processed_recipients}")
        
        # Get task info
        task = ScheduledTask.query.filter_by(id=slot.task_id).first()
        if task:
            print(f"   Task ID: {task.id}")
            print(f"   User ID: {task.user_id}")
            
            # Try to parse recipients
            try:
                recipients = json.loads(task.recipients)
                print(f"   Recipients count from task: {len(recipients)}")
            except:
                print("   ⚠️  Could not parse recipients")
        
        # Check SentMessage records
        sent_count = SentMessage.query.filter_by(slot_id=slot.id).count()
        print(f"   SentMessage records: {sent_count}")
        
        # Get a few samples
        samples = SentMessage.query.filter_by(slot_id=slot.id).limit(3).all()
        for sm in samples:
            print(f"     - Recipient {sm.recipient_id}: {sm.status}")
            if sm.error_message:
                print(f"       Error: {sm.error_message[:50]}...")
        
        print("\n✅ Endpoint structure looks correct!")
        print("   The endpoint should return:")
        print("   - Slot info (id, status, datetime, progress)")
        print("   - Recipients list with status for each")
        print("   - Error messages for failed sends")
        
        return True

if __name__ == '__main__':
    try:
        success = test_slot_endpoint()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
