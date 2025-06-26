from datetime import datetime
from collections import defaultdict
import re
from typing import Dict, List, Any
import ipaddress
from collections import Counter
from analysis_db import AnalysisDB

class MessageAnalyzer:
    def __init__(self):
        self.db = AnalysisDB()
        self.messages = []
        self.message_stats = {
            'total_messages': 0,
            'messages_per_client': defaultdict(int),
            'messages_per_hour': defaultdict(int),
            'average_message_length': 0,
            'word_frequency': defaultdict(int),
            'client_ips': set(),
            'connection_attempts': defaultdict(int),
            'disconnection_events': defaultdict(int),
            'error_events': defaultdict(int)
        }
        self.client_details = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'total_messages': 0,
            'total_bytes': 0,
            'error_count': 0,
            'connection_count': 0
        })
        self.connection_events_per_hour = defaultdict(int)
        self.load_from_db()

    def load_from_db(self):
        # Load messages
        for client_address, message, timestamp in self.db.load_messages():
            self._add_message_internal(client_address, message, timestamp, save_to_db=False)
        # Load connections
        for client_address, event, timestamp in self.db.load_connections():
            if event == 'connect':
                self.record_connection(timestamp)
            elif event == 'disconnect':
                self.mark_disconnected(client_address, timestamp)

    def _add_message_internal(self, client_address: str, message: str, timestamp: datetime, save_to_db=True):
        """Add a new message to the analyzer."""
        # Parse client address
        try:
            ip, port = client_address.split(':')
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private
        except:
            ip = client_address
            port = 'unknown'
            is_private = False

        # Update client details
        client_info = self.client_details[client_address]
        if client_info['first_seen'] is None:
            client_info['first_seen'] = timestamp
        client_info['last_seen'] = timestamp
        client_info['total_messages'] += 1
        client_info['total_bytes'] += len(message.encode())
        client_info['connection_count'] += 1

        # Add message to history
        self.messages.append({
            'client': client_address,
            'ip': ip,
            'port': port,
            'is_private': is_private,
            'message': message,
            'timestamp': timestamp,
            'length': len(message)
        })
        
        # Update statistics
        self.message_stats['total_messages'] += 1
        self.message_stats['messages_per_client'][client_address] += 1
        self.message_stats['messages_per_hour'][timestamp.hour] += 1
        self.message_stats['client_ips'].add(ip)
        
        # Update word frequency
        words = re.findall(r'\b\w+\b', message.lower())
        for word in words:
            self.message_stats['word_frequency'][word] += 1
        
        # Update average message length
        total_length = sum(msg['length'] for msg in self.messages)
        self.message_stats['average_message_length'] = total_length / len(self.messages)

        if save_to_db:
            self.db.save_message(client_address, message, timestamp)

    def add_message(self, client_address: str, message: str, timestamp: datetime):
        self._add_message_internal(client_address, message, timestamp, save_to_db=True)

    def get_analysis(self) -> Dict[str, Any]:
        """Get the current analysis results."""
        # Calculate message sizes
        if self.messages:
            sizes = [len(msg['message'].encode()) for msg in self.messages]
            avg_size = sum(sizes) / len(sizes)
            max_size = max(sizes)
        else:
            avg_size = 0
            max_size = 0
        # Find most frequent message
        if self.messages:
            msg_texts = [msg['message'] for msg in self.messages]
            most_common = Counter(msg_texts).most_common(1)
            frequent_message = most_common[0][0] if most_common else ''
        else:
            frequent_message = ''
        return {
            'total_messages': self.message_stats['total_messages'],
            'messages_per_client': dict(self.message_stats['messages_per_client']),
            'messages_per_hour': dict(self.message_stats['messages_per_hour']),
            'average_message_length': round(self.message_stats['average_message_length'], 2),
            'top_words': dict(sorted(
                self.message_stats['word_frequency'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),  # Top 10 most frequent words
            'unique_clients': len(self.message_stats['client_ips']),
            'private_ips': sum(1 for msg in self.messages if msg.get('is_private', False)),
            'public_ips': sum(1 for msg in self.messages if not msg.get('is_private', False)),
            'frequent_message': frequent_message,
            'average_message_size': round(avg_size, 2),
            'max_message_size': max_size
        }

    def get_client_statistics(self) -> Dict[str, Any]:
        """Get detailed client statistics."""
        stats = {}
        now = datetime.now()
        for client, info in self.client_details.items():
            # If client is active, use now as last_seen for real-time total time
            if info['first_seen']:
                if info['last_seen'] and (now - info['last_seen']).total_seconds() < 300:
                    total_time = (now - info['first_seen']).total_seconds()
                elif info['last_seen']:
                    total_time = (info['last_seen'] - info['first_seen']).total_seconds()
                else:
                    total_time = 0
            else:
                total_time = 0
            stats[client] = {
                'first_seen': info['first_seen'].strftime('%Y-%m-%d %H:%M:%S') if info['first_seen'] else '-',
                'last_seen': info['last_seen'].strftime('%Y-%m-%d %H:%M:%S') if info['last_seen'] else '-',
                'total_messages': info['total_messages'],
                'total_bytes': info['total_bytes'],
                'connection_count': info['connection_count'],
                'total_time_connected': int(total_time)
            }
        return {
            'total_clients': len(self.client_details),
            'active_clients': sum(1 for info in self.client_details.values() 
                                if (datetime.now() - info['last_seen']).total_seconds() < 300),
            'client_details': stats
        }

    def get_security_statistics(self) -> Dict[str, Any]:
        """Get security-related statistics."""
        return {
            'total_connections': sum(info['connection_count'] for info in self.client_details.values()),
            'total_errors': sum(info['error_count'] for info in self.client_details.values()),
            'private_ip_connections': sum(1 for msg in self.messages if msg.get('is_private', False)),
            'public_ip_connections': sum(1 for msg in self.messages if not msg.get('is_private', False)),
            'error_rate': round(
                sum(info['error_count'] for info in self.client_details.values()) /
                sum(info['connection_count'] for info in self.client_details.values()) * 100
                if sum(info['connection_count'] for info in self.client_details.values()) > 0 else 0,
                2
            )
        }

    def get_recent_messages(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent messages."""
        return self.messages[-limit:]

    def mark_disconnected(self, client_address: str, timestamp=None):
        """Mark a client as disconnected by updating last_seen to now."""
        if client_address in self.client_details:
            if timestamp is None:
                timestamp = datetime.now()
            self.client_details[client_address]['last_seen'] = timestamp
            self.db.save_connection_event(client_address, 'disconnect', timestamp)

    def record_connection(self, timestamp: datetime):
        self.connection_events_per_hour[timestamp.hour] += 1
        # Save to DB (client_address is not tracked here, so skip or pass as needed)
        # This method is called from web_interface, which can pass client_address if needed

    def get_connection_stats_per_hour(self):
        hourly = [0] * 24
        for hour, count in self.connection_events_per_hour.items():
            hourly[int(hour)] = count
        return hourly 