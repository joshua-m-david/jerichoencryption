#!/bin/bash
#
# Jericho Comms - Information-theoretically secure communications
# Copyright (c) 2013-2019  Joshua M. David
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation in version 3 of the License.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].


# This script stops the NTP service, force synchronises
# the time to an NTP server and restarts the NTP service
service ntp stop
ntpd -gq
service ntp start
