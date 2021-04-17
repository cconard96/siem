<?php
/**
 *  -------------------------------------------------------------------------
 *  SIEM plugin for GLPI
 *  Copyright (C) 2019 by Curtis Conard
 *  https://github.com/cconard96/siem
 *  -------------------------------------------------------------------------
 *  LICENSE
 *  This file is part of SIEM plugin for GLPI.
 *  SIEM plugin for GLPI is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  SIEM plugin for GLPI is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with SIEM plugin for GLPI. If not, see <http://www.gnu.org/licenses/>.
 */

namespace GlpiPlugin\SIEM\Sensor;

use CommonDBTM;
use GlpiPlugin\SIEM\Event;
use GlpiPlugin\SIEM\Host;
use GlpiPlugin\SIEM\Service;

class HTTP extends Sensor {

   public static function poll($service_ids = [])
   {
      foreach ($service_ids as $service_id) {
         $service = new Service();
         if (!$service->getFromDB($service_id)) {
            return false;
         }
         $hosts_id = $service->fields['plugin_siem_hosts_id'];
         $host = new Host();
         if (!$host->getFromDB($hosts_id)) {
            return [];
         }
         $hosttype = $host->fields['itemtype'];
         /** @var CommonDBTM $host_item */
         $host_item = new $hosttype();
         if (!$host_item->getFromDB($host->fields['items_id'])) {
            return [];
         }

         $ch = curl_init();
         curl_setopt($ch, CURLOPT_URL, $host_item->fields['name']);
         curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
         $output = curl_exec($ch);
         $info = curl_getinfo($ch);

         if (curl_error($ch)) {
            curl_close($ch);
            $results[$service_id] = [
               'name' => 'sensor_http_ok_error',
               'significance' => Event::EXCEPTION,
               'date' => $_SESSION['glpi_currenttime'],
               'content' => json_encode([
                  'errorno'   => curl_errno($ch),
                  'error_msg' => curl_error($ch)
               ]),
            ];
         } else {
            curl_close($ch);
            $httpcode = $info['http_code'];
            $totaltime = $info['total_time'];
            $download_size = $info['size_download'];

            if ($httpcode === 200) {
               $results[$service_id] = [
                  'name' => 'sensor_http_ok_ok',
                  'significance' => Event::INFORMATION,
                  'date' => $_SESSION['glpi_currenttime'],
                  'content' => json_encode([
                     'response_time'   => $totaltime,
                     'response_size'   => $download_size
                  ])
               ];
            } else {
               $results[$service_id] = [
                  'name' => 'sensor_http_ok_error',
                  'significance' => Event::WARNING,
                  'date' => $_SESSION['glpi_currenttime'],
                  'content' => json_encode([
                     'http_code'       => $httpcode,
                     'response_time'   => $totaltime,
                     'response_size'   => $download_size
                  ])
               ];
            }
         }
      }

      return $results;
   }
}