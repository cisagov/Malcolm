#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

import subprocess
import socket
import string
from sensorcommon import *

LABEL_HDD = "Storage device"
HDDTEMP_PORT_DEFAULT=7634
HDDTEMP_INTERFACE_IP="127.0.0.1"

class Metric(object):

  def __init__(self, adapter_id, sensor_id, sensor_key, value, label):
    self._value = self.parse_value(value)
    self._adapter_id = adapter_id
    self._sensor_id = sensor_id
    self._sensor_key = sensor_key
    self._label = label
    if (label.startswith('Core') or
        label.startswith('Processor') or
        ((label.startswith('Physical') or label.startswith('Package')) and adapter_id.startswith('core'))):
      self._label_class = "cpu"
    elif LABEL_HDD in label:
      self._label_class = "hdd"
    elif "GPU" in label:
      self._label_class = "gpu"
    elif "DIMM" in label:
      self._label_class = "memory"
    else:
      self._label_class = "other"

  @classmethod
  def parse_value(cls, value):
    if hasattr(cls, "parse"):
      parse = getattr(cls, "parse")
      return parse(value)
    else:
      return value

  def to_dictionary(self):
    return {
      "name": self._sensor_id,
      "adapter": self._adapter_id,
      "value": self._value,
      "value_type": self.parse.__name__,
      "units": getattr(self, "unit", "?"),
      "label": self._label,
      "class": "%s%s" % (self._label_class, getattr(self, "suffix", ""))
    }

  def __repr__(self):
    return "%s, %s, %s: %s %s [%s]" % (
      self._adapter_id,
      self._sensor_id,
      self._sensor_key,
      self._value,
      getattr(self, "unit", "?"),
      self._label)

class TemperatureMetric(Metric):
  parse = float
  unit = "°C"
  suffix = "_temp"

class FanMetric(Metric):
  parse = float
  unit = "RPM"
  suffix = "_rpm"

class VoltageMetric(Metric):
  parse = float
  unit = "V"
  suffix = "_volt"

def metric_cleanup():
  pass

def get_metrics_list(HddTempHost=HDDTEMP_INTERFACE_IP, HddTempPort=HDDTEMP_PORT_DEFAULT):

  # lm-sensors values
  try:
    output = subprocess.check_output(["/usr/bin/sensors", "-u"], stderr=subprocess.DEVNULL).decode("utf-8").strip()
  except Exception as e:
    eprint(e)
    output = []
  sections = output.split("\n\n")

  metrics = []
  for section in sections:
    fields = section.split("\n")
    adapter_id = fields[0]

    label = None
    for field in fields[2:]:
      if field.startswith("  "):
        field = field.replace("  ", "")
        field_key, field_value = field.split(": ")
        if "_" in field_key:
          sensor_id, sensor_key = field_key.split("_", 1)
          if sensor_key == "input":
            if sensor_id.startswith("temp"):
              metrics.append(TemperatureMetric(adapter_id, sensor_id, sensor_key, field_value, label=label))
            elif sensor_id.startswith("in"):
              metrics.append(VoltageMetric(adapter_id, sensor_id, sensor_key, field_value, label=label))
            elif sensor_id.startswith("fan"):
                metrics.append(FanMetric(adapter_id, sensor_id, sensor_key, field_value, label=label))
      else:
        label = field[:-1] # strip off trailing ":" character


  # connect to hddtemp daemon for HDD temperature monitoring
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
      try:
        s.connect((HDDTEMP_INTERFACE_IP, HDDTEMP_PORT_DEFAULT))
        hdd_temp_line = ""
        data = s.recv(4096)
        while data:
          hdd_temp_line += data.decode('latin-1')
          data = s.recv(4096)
        for hdd_stats in [x.split('|') for x in hdd_temp_line.strip('|').split('||')]:
          if (len(hdd_stats) == 4) and isfloat(hdd_stats[2]):
            metrics.append(TemperatureMetric(' '.join(''.join(filter(lambda x: x in string.printable, hdd_stats[1])).split()),
                                             hdd_stats[0],
                                             'input',
                                             hdd_stats[2],
                                             label=LABEL_HDD))
      except Exception as e:
        eprint(e)
        pass
    finally:
      s.shutdown(2)
      s.close()

  return metrics
