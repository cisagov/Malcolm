#!/usr/bin/env bash

set -euo pipefail

if (( EUID != 0 )); then
    printf 'Run this test with sudo: sudo %s\n' "$0" >&2
    exit 2
fi

model_text="$(tr -d '\000' < /proc/device-tree/model 2>/dev/null || true)"
case "$model_text" in
    *"Raspberry Pi 5"*|*"Raspberry Pi 500"*|*"Compute Module 5"*)
        ;;
    *"Raspberry Pi 4"*|*"Raspberry Pi 400"*|*"Compute Module 4"*)
        printf 'SKIP: Raspberry Pi 4 has no standard onboard PWM fan controller.\n'
        exit 0
        ;;
    *)
        printf 'FAIL: unsupported or unidentified hardware: %s\n' "${model_text:-unknown}" >&2
        exit 2
        ;;
esac

fan_device=""
for device in /sys/class/thermal/cooling_device*; do
    [[ -r "$device/type" ]] || continue
    if [[ "$(< "$device/type")" == "pwm-fan" ]]; then
        fan_device="$device"
        break
    fi
done

if [[ -z "$fan_device" ]]; then
    printf 'FAIL: pwm-fan cooling device is missing\n' >&2
    exit 1
fi

fan_input=""
fan_pwm=""
for hwmon in /sys/class/hwmon/hwmon*; do
    [[ -r "$hwmon/name" ]] || continue
    if [[ "$(< "$hwmon/name")" == "pwmfan" ]]; then
        [[ -r "$hwmon/fan1_input" ]] && fan_input="$hwmon/fan1_input"
        [[ -r "$hwmon/pwm1" ]] && fan_pwm="$hwmon/pwm1"
        break
    fi
done

original_state="$(< "$fan_device/cur_state")"
max_state="$(< "$fan_device/max_state")"

restore_fan() {
    printf '%s\n' "$original_state" > "$fan_device/cur_state"
}
trap restore_fan EXIT INT TERM

temperature="$(< /sys/class/thermal/thermal_zone0/temp)"
awk -v value="$temperature" 'BEGIN { printf "Temperature: %.1f C\n", value / 1000 }'
printf 'Fan device: %s\n' "$fan_device"
printf 'Original state: %s/%s\n' "$original_state" "$max_state"
printf 'Setting state %s for five seconds. Watch and listen for the fan.\n' "$max_state"

printf '%s\n' "$max_state" > "$fan_device/cur_state"
sleep 1
printf 'Reported state: %s/%s\n' "$(< "$fan_device/cur_state")" "$max_state"
[[ -n "$fan_pwm" ]] && printf 'PWM: %s\n' "$(< "$fan_pwm")"
[[ -n "$fan_input" ]] && printf 'RPM: %s\n' "$(< "$fan_input")"
sleep 4

restore_fan
trap - EXIT INT TERM
printf 'Restored state: %s/%s\n' "$(< "$fan_device/cur_state")" "$max_state"
printf 'CHECK: confirm that the fan spun physically during the test.\n'
printf 'INFO: an RPM value of zero is normal for fans without a tachometer signal.\n'
