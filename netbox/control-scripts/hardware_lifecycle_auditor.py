import json
import requests
from django.utils import timezone
from django.forms import PasswordInput
from extras.scripts import Script, StringVar, FileVar, ChoiceVar
from dcim.models import Device
from extras.models import Tag

class HardwareLifecycleAuditor(Script):
    class Meta:
        name = "Hardware Lifecycle Scanner (Universal)"
        description = "Scans active inventory against lifecycle data to identify End-of-Support devices, tags them, and outputs a CSV report"
        field_order = ['remote_feed_url', 'auth_type', 'auth_token', 'local_feed_file']

    remote_feed_url = StringVar(label="Remote API Feed URL", required=False)
    
    auth_type = ChoiceVar(
        choices=(
            ('Bearer', 'Bearer (Standard API Token)'),
            ('token', 'Token (GitHub)'),
            ('Basic', 'Basic (Legacy Systems)'),
            ('', 'None/Custom'),
        ),
        default='Bearer',
        required=False
    )
    
    auth_token = StringVar(label="API Token", required=False, widget=PasswordInput)
    local_feed_file = FileVar(label="Local JSON File", required=False)

    def run(self, data, commit):
        SCHEMA_CONFIG = {
            "date_identifiers": {'end_of_support_date', 'eos_date', 'eol_date', 'LastDateOfSupport', 'EndOfLife', 'value'},
            "model_identifiers": {'EOLProductID', 'model', 'product_id', 'part_number', 'name'},
            "metadata_keys": {'PaginationResponseRecord', 'total_count', 'page_index', 'products', 'EOXRecord'}
        }
        eos_tag, _ = Tag.objects.get_or_create(
            slug='lifecycle-end-of-support',
            defaults={'name': 'Lifecycle: End of Support', 'color': 'ff0000'}
        )
        supported_tag, _ = Tag.objects.get_or_create(
            slug='lifecycle-supported',
            defaults={'name': 'Lifecycle: Supported', 'color': '00ff00'}
        )
        raw_data = self._get_raw_data(data)
        if not raw_data: 
            return "❌ Audit Aborted: No valid data source provided."
        normalized_map = {}
        def extract_lifecycle(obj, current_model=None):
            """Generic recursive crawler: Pairs model identity with date values."""
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in SCHEMA_CONFIG["date_identifiers"] and isinstance(v, (str, dict)):
                        date_str = v.get('value') if isinstance(v, dict) else v
                        if current_model and isinstance(date_str, str) and date_str.strip():
                            normalized_map[current_model] = date_str.strip()
                    else:
                        next_model = current_model
                        if k not in SCHEMA_CONFIG["metadata_keys"] and k != 'value':
                            next_model = k if not current_model else current_model
                        extract_lifecycle(v, next_model)            
            elif isinstance(obj, list):
                for item in obj:
                    potential_model = current_model
                    if isinstance(item, dict):
                        for m_key in SCHEMA_CONFIG["model_identifiers"]:
                            if item.get(m_key):
                                potential_model = item.get(m_key)
                                break
                    extract_lifecycle(item, potential_model)

        extract_lifecycle(raw_data)
        self.log_info(f"Crawler successfully discovered {len(normalized_map)} lifecycle records in the JSON payload.")
        devices = Device.objects.filter(status='active')
        self.log_info(f"Auditing {devices.count()} active devices in NetBox...")
        
        now = timezone.now().date()
        stats = {"comp": 0, "non": 0, "skipped": 0}
        csv_rows = ["Device,Model,EOS Date,Status"]

        for device in devices:
            model = device.device_type.model
            eos_str = normalized_map.get(model)

            if eos_str:
                try:
                    eos_dt = timezone.datetime.strptime(eos_str[:10], '%Y-%m-%d').date()
                    is_eos = eos_dt < now
                    
                    if is_eos:
                        device.tags.add(eos_tag)
                        device.tags.remove(supported_tag)
                        status_label = "End-of-Support"
                        stats["non"] += 1
                        self.log_warning(f"ACTION REQUIRED: {device.name} ({model}) reached EOS on {eos_dt}")
                    else:
                        device.tags.add(supported_tag)
                        device.tags.remove(eos_tag)
                        status_label = "Supported"
                        stats["comp"] += 1
                        self.log_success(f"COMPLIANT: {device.name} ({model}) supported until {eos_dt}")
                    
                    if commit: 
                        device.save()
                        
                    csv_rows.append(f"{device.name},{model},{eos_dt},{status_label}")
                except Exception as e:
                    self.log_failure(f"Failed to parse date '{eos_str}' for {model}: {str(e)}")
                    continue
            else:
                stats["skipped"] += 1
                self.log_info(f"Skipped: {device.name} ({model}) - No matching data in payload.")

        return f"Audit Complete. Supported: {stats['comp']} | EOS: {stats['non']} | Skipped: {stats['skipped']}\n" + "-"*40 + "\n" + "\n".join(csv_rows)

    def _get_raw_data(self, data):
        if data.get('local_feed_file'):
            self.log_info("Reading uploaded local file...")
            return json.loads(data['local_feed_file'].read())
        
        url = data.get('remote_feed_url')
        if url:
            headers = {}
            if data.get('auth_token'):
                headers["Authorization"] = f"{data.get('auth_type')} {data.get('auth_token')}".strip()
            
            try:
                res = requests.get(url, headers=headers, timeout=15)
                res.raise_for_status()
                return res.json()
            except Exception as e:
                self.log_failure(f"Network error: {str(e)}")
        return None