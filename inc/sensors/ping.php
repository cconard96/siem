<?php

use Symfony\Component\Process\Process;

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


class PluginSiemSensorPing extends PluginSiemSensor
{

   protected static function poll($service_ids = [])
   {
      $defparams = [
         'name_first' => true,
      ];
      $hosts = [];
      foreach ($service_ids as $services_id) {
         $service = new PluginSiemService();
         if (!$service->getFromDB($services_id)) {
            return false;
         }
         if (isset($service->fields['sensor_params'])) {
            $sensor_params = json_decode($service->fields['sensor_params'], true);
         } else {
            $sensor_params = $defparams;
         }
         $sensor_params = array_replace($defparams, $sensor_params);
         $hosts_id = $service->fields['plugin_siem_hosts_id'];
         $host = new PluginSiemHost();
         if (!$host->getFromDB($hosts_id)) {
            return [];
         }
         $hosttype = $host->fields['itemtype'];
         /** @var CommonDBTM $host_item */
         $host_item = new $hosttype();
         if (!$host_item->getFromDB($host->fields['items_id'])) {
            return [];
         }
         if ($sensor_params['name_first']) {
            $hosts[$services_id] = $host_item->fields['name'];
         } else {
         }
      }
      $results = self::tryPing($hosts);
      $eventdatas = [];
      foreach ($results as $services_id => $result) {
         if (!isset($result['_sensor_fault'])) {
            $eventdata = self::getPingEventData($services_id, $result);
         } else {
            $eventdata = null;
         }
         if ($eventdata !== null) {
            $eventdatas[$services_id] = $eventdata;
         }
      }
      return $eventdatas;
   }

   private static function getPingEventData($services_id, $ping_result)
   {
      $event = new PluginSiemEvent();
      $event_content = [];
      if (isset($ping_result['percent_loss'], $ping_result['min']) && isset($ping_result['avg']) && isset($ping_result['max']) && isset($ping_result['mdev'])) {
         $event_content['percent_loss'] = $ping_result['percent_loss'];
         $event_content['min'] = $ping_result['min'];
         $event_content['avg'] = $ping_result['avg'];
         $event_content['max'] = $ping_result['max'];
         $event_content['mdev'] = $ping_result['mdev'];
      } else if (!isset($ping_result['_sensor_fault'])) {
         return [
            'name' => 'sensor_ping_notok',
            'status' => PluginSiemEvent::STATUS_NEW,
            'significance' => PluginSiemEvent::EXCEPTION,
            'date' => $_SESSION['glpi_currenttime'],
            'content' => json_encode($ping_result),
         ];
      } else {
         //Sensor parse error
         return [
            'name' => 'sensor_ping_error',
            'status' => PluginSiemEvent::STATUS_NEW,
            'significance' => PluginSiemEvent::EXCEPTION,
            'date' => $_SESSION['glpi_currenttime'],
            'content' => json_encode($event_content),
            '_sensor_fault' => true
         ];
      }
      if ($event_content['percent_loss'] > 0) {
         return [
            'name' => 'sensor_ping_warn',
            'status' => PluginSiemEvent::STATUS_NEW,
            'significance' => PluginSiemEvent::WARNING,
            'date' => $_SESSION['glpi_currenttime'],
            'content' => json_encode($event_content),
         ];
      } else {
         return [
            'name' => 'sensor_ping_ok',
            'status' => PluginSiemEvent::STATUS_NEW,
            'significance' => PluginSiemEvent::INFORMATION,
            'date' => $_SESSION['glpi_currenttime'],
            'content' => json_encode($event_content),
         ];
      }
   }

   private static function tryPing($hosts, $count = 5)
   {
      $results = [];
      $sub_processes = [];
      foreach ($hosts as $service_id => $host) {
         $result = [];
         $process = new Process(['/bin/ping', "-c $count", $host]);
         $process->start();
         $sub_processes[$service_id] = $process;
      }
      // Wait for pings to finish
      $done = true;
      do {
         foreach ($sub_processes as $subprocess) {
            $subprocess->wait();
         }
      } while (!$done);
      // Parse results
      foreach ($sub_processes as $service_id => $process) {
         $exitcode = $process->getExitCode();
         if (0 !== $exitcode) {
            if (1 === $exitcode) {
               $result = [
                  'exit_code' => $exitcode,
                  'error_msg' => "No response in $count tries",
               ];
            } else {
               $result = [
                  'exit_code' => $exitcode,
                  'error_msg' => $process->getErrorOutput(),
               ];
            }
            $results[$service_id] = $result;
            continue;
         }
         $pingresult = $process->getOutput();
         try {
            $outcome = $pingresult;
            if (preg_match('/(received, )(.*?)(packet)/', $outcome, $match) === 1) {
               $result['percent_loss'] = str_replace('%', '', trim($match[2]));
            } else {
               throw new RuntimeException('Malformed sensor output');
            }
            if ($result['percent_loss'] !== '100' && preg_match('/(rtt)(.*?)(=)(.*?)(ms)/', $outcome, $match) === 1) {
               $values = explode('/', trim($match[4]));
               $result['min'] = $values[0];
               $result['avg'] = $values[1];
               $result['max'] = $values[2];
               $result['mdev'] = $values[3];
               $results[$service_id] = $result;
            } else if ($result['percent_loss'] !== '100') {
               throw new RuntimeException('Malformed sensor output');
            }
         } catch (RuntimeException $e) {
            $result = [
               '_sensor_fault' => true,
               'exit_code' => $exitcode,
               'error_msg' => $process->getErrorOutput()
            ];
            $results[$service_id] = $result;
         }
      }
      return $results;
   }
}