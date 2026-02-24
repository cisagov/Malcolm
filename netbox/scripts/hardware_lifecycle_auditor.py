from extras.scripts import Script, StringVar, FileVar
from dcim.models import Device
from extras.models import Tag
from django.utils import timezone
import json
import requests

class HardwareLifecycleAuditor(Script):
    class Meta:
        name = "Hardware Lifecycle Scanner (OpenEoX)"
        description = "Scans active inventory against lifecycle data to identify End-of-Support devices, tags them, and outputs a CSV report."
        field_order = ['remote_feed_url', 'auth_header', 'local_feed_file']

    remote_feed_url = StringVar(
        label="Remote OpenEoX Feed URL",
        description="URL to a machine-readable JSON feed. Leave blank if uploading a file.",
        default="",
        required=False
    )

    auth_header = StringVar(
        label="API Token / Auth Header (Optional)",
        description="Format: 'Bearer YOUR_TOKEN' or 'token YOUR_GITHUB_PAT'. Required for private Git repos or authenticated internal APIs.",
        required=False
    )

    local_feed_file = FileVar(
        label="Local OpenEoX File",
        description="Upload a local JSON file if operating in an air-gapped environment.",
        required=False
    )

    def run(self, data, commit):
        # NetBox Tags for Malcolm Dashboard Enrichment
        eos_tag, _ = Tag.objects.get_or_create(
            name='Lifecycle: End of Support',
            slug='lifecycle-end-of-support',
            defaults={'color': 'ff0000', 'description': 'Device has reached End of Support and is a security risk.'}
        )
        
        supported_tag, _ = Tag.objects.get_or_create(
            name='Lifecycle: Supported',
            slug='lifecycle-supported',
            defaults={'color': '00ff00', 'description': 'Device is actively supported by the vendor.'}
        )

        #Load the Lifecycle Data
        eos_data = {}
        
        if data.get('local_feed_file'):
            self.log_info("Loading lifecycle data from uploaded file...")
            try:
                eos_data = json.loads(data['local_feed_file'].read())
            except Exception as e:
                self.log_failure(f"Failed to parse uploaded file as JSON: {e}")
                return "❌ Audit Aborted: Failed to parse uploaded file."
                
        elif data.get('remote_feed_url'):
            self.log_info(f"Fetching remote lifecycle feed from {data['remote_feed_url']}...")
            
            headers = {}
            if data.get('auth_header'):
                headers['Authorization'] = data['auth_header']
                self.log_info("Applying provided Authentication header...")

            try:
                response = requests.get(data['remote_feed_url'], headers=headers, timeout=10)
                if response.status_code == 200:
                    eos_data = response.json()
                else:
                    self.log_failure(f"HTTP Error {response.status_code}: The remote URL is broken or authentication failed.")
                    return f"❌ Audit Aborted: HTTP Error {response.status_code}."
            except ValueError as e:
                self.log_failure(f"JSON Parsing Error: The remote server did not return valid JSON. ({e})")
                return "❌ Audit Aborted: Invalid JSON received from remote server."
            except Exception as e:
                self.log_failure(f"Network error while fetching remote feed: {e}")
                return f"❌ Audit Aborted: Network error ({e})."

        if not eos_data:
            self.log_failure("No lifecycle data available to perform audit.")
            return "❌ Audit Aborted: No valid lifecycle data was provided."

        #Query NetBox Inventory
        devices = Device.objects.filter(status='active')
        self.log_info(f"Scanning {devices.count()} active devices for hardware lifecycle compliance...")

        now = timezone.now().date()
        compliant_count = 0
        non_compliant_count = 0

        # Prepare CSV Output String
        csv_output = "Device Name,Device Model,EOS Date,Status\n"

        #Audit and Tag Devices
        for device in devices:
            model_name = device.device_type.model
            lifecycle_info = eos_data.get(model_name)

            if lifecycle_info:
                eos_date_str = lifecycle_info.get('end_of_support_date')
                if eos_date_str:
                    eos_date = timezone.datetime.strptime(eos_date_str, '%Y-%m-%d').date()
                    
                    if eos_date < now:
                        device.tags.add(eos_tag)
                        device.tags.remove(supported_tag)
                        device.save()
                        
                        self.log_warning(f"ACTION REQUIRED: {device.name} ({model_name}) reached End-of-Support on {eos_date}.")
                        csv_output += f"{device.name},{model_name},{eos_date},End-of-Support\n"
                        non_compliant_count += 1
                    else:
                        device.tags.add(supported_tag)
                        device.tags.remove(eos_tag)
                        device.save()
                        
                        self.log_success(f"COMPLIANT: {device.name} ({model_name}) is supported until {eos_date}.")
                        csv_output += f"{device.name},{model_name},{eos_date},Supported\n"
                        compliant_count += 1
            else:
                self.log_debug(f"Skipping {device.name}: No OpenEoX lifecycle data found for model '{model_name}'.")

        self.log_info(f"Audit Complete. Supported: {compliant_count}, End-of-Support: {non_compliant_count}")

        #Return the final summary and CSV format
        summary = f"Audit Complete. Supported: {compliant_count} | End-of-Support: {non_compliant_count}\n"
        summary += "-" * 50 + "\n"
        summary += "CSV EXPORT:\n"
        summary += csv_output

        return summary

