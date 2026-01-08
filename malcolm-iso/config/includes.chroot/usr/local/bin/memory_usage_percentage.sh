#!/bin/sh

free -t | awk 'FNR == 2 {printf("%.2f\n"), $3/$2*100}'