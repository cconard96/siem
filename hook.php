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

use GlpiPlugin\SIEM\DBUtil;
use GlpiPlugin\SIEM\Event;
use GlpiPlugin\SIEM\Sensor\HTTP;
use GlpiPlugin\SIEM\Sensor\Ping;

function plugin_siem_install()
{
   $migration = new \GlpiPlugin\SIEM\Migration(PLUGIN_SIEM_VERSION);
   $migration->applyMigrations();
   return true;
}

function plugin_siem_uninstall()
{
   DBUtil::dropTableOrDie('glpi_plugin_siem_events');
   DBUtil::dropTableOrDie('glpi_plugin_siem_itils_events');
   DBUtil::dropTableOrDie('glpi_plugin_siem_hosts');
   DBUtil::dropTableOrDie('glpi_plugin_siem_services');
   DBUtil::dropTableOrDie('glpi_plugin_siem_servicetemplates');
   DBUtil::dropTableOrDie('glpi_plugin_siem_itils_scheduleddowntimes');
   DBUtil::dropTableOrDie('glpi_plugin_siem_scheduleddowntimes');
   DBUtil::dropTableOrDie('glpi_plugin_siem_acknowledgements');
   Config::deleteConfigurationValues('plugin:siem');
   CronTask::unregister('siem');
   return true;
}

function plugin_siem_poll_sensor(array $params)
{
   if (!isset($params['sensor']) || !isset($params['service_ids'])) {
      return [];
   }
   switch ($params['sensor']) {
      case 'ping':
         return Ping::poll($params['service_ids']);
      case 'http_ok':
         return HTTP::poll($params['service_ids']);
   }
}

function plugin_siem_get_sensor_params(string $sensor) {
   $glpi_status_sensors = ['glpi_cas', 'glpi_crontask', 'glpi_db', 'glpi_filesystem', 'glpi_imap', 'glpi_ldap',
      'glpi_mailcollector', 'glpi_plugin'];
   if (in_array($sensor, $glpi_status_sensors)) {
      return [
         'glpi_path' => [
            'label'     => __('GLPI Path', 'siem'),
            'default'   => '/'
         ]
      ];
   }
}

function plugin_siem_translateEventName($name) {
   switch ($name) {
      case 'sensor_ping_ok':
         return __('Ping OK', 'siem');
      case 'sensor_ping_notok':
         return __('Ping not OK', 'siem');
      case 'sensor_http_ok_ok':
         return __('HTTP OK', 'siem');
      case 'sensor_http_ok_error':
         return __('HTP not OK', 'siem');
      default:
         return $name;
   }
}

function plugin_siem_translateEventProperties($props) {
   foreach ($props as $name => &$params) {
      switch ($name) {
         case 'percent_loss':
            $params['name'] = __('Percent loss', 'siem');
            break;
         case 'min':
            $params['name'] = __('Minimum (ms)', 'siem');
            break;
         case 'avg':
            $params['name'] = __('Average (ms)', 'siem');
            break;
         case 'max':
            $params['name'] = __('Maximum (ms)', 'siem');
            break;
         case 'mdev':
            $params['name'] = __('Standard deviation (ms)', 'siem');
            break;
         case 'http_code':
            $params['name'] = __('HTTP code', 'siem');
            break;
         case 'response_time':
            $params['name'] = __('Response time (ms)', 'siem');
            break;
         case 'response_size':
            $params['name'] = __('Response size (bytes)', 'siem');
            break;
      }
   }
   return $props;
}

//function plugin_siem_getAddSearchOptions($itemtype)
//{
//   $opt = [];
//   if (method_exists($itemtype, 'getAddSearchOptions')) {
//      $opt = call_user_func([$itemtype, 'getAddSearchOptions']);
//   }
//   return $opt;
//}