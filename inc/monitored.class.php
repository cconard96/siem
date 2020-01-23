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


if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

/**
 * Trait for shared functions between Event Management hosts and services.
 * @since 1.0.0
 **/
trait PluginSiemMonitored
{
   private function getMonitoredField($field)
   {
      if (static::getType() === 'PluginSiemHost') {
         $service = $this->getAvailabilityService();
         if ($service) {
            return $service->fields[$field];
         } else {
            return null;
         }
      } else {
         return $this->fields[$field];
      }
   }

   public function isAlertState()
   {
      $status = $this->getStatus();
      return $status !== 0 && $status !== 2;
   }

   /**
    * Returns true if the host or service is currently flapping.
    * @since 1.0.0
    */
   public function isFlapping()
   {
      $flapping = $this->getMonitoredField('is_flapping');
      return ($flapping !== null && $flapping);
   }

   public function getStatus()
   {
      $status = $this->getMonitoredField('status');
      return $status !== null ? $status : PluginSiemHost::STATUS_UNKNOWN;
   }

   public function isHardStatus()
   {
      $flapping = $this->getMonitoredField('is_hard_status');
      return ($flapping !== null && $flapping);
   }

   public function getLastStatusCheck()
   {
      return $this->getMonitoredField('last_check');
   }

   public function getLastStatusChange()
   {
      return $this->getMonitoredField('status_since');
   }

   /**
    * Returns the translated name of the host or service's current status.
    * @since 1.0.0
    */
   public function getCurrentStatusName()
   {
      if (static::getType() === 'PluginSiemHost') {
         if ($this->fields['is_reachable']) {
            return PluginSiemHost::getStatusName($this->getStatus());
         } else {
            return __('Unreachable');
         }
      } else {
         return PluginSiemHost::getStatusName($this->getStatus());
      }
   }

   /**
    * Returns true if the host or service is scheduled for downtime right now.
    * @since 1.0.0
    */
   public function isScheduledDown()
   {
      static $is_scheduleddown = null;
      if ($is_scheduleddown === null) {
         $iterator = PluginSiemScheduledDowntime::getForHostOrService($this->getID(), static::class == 'PluginSiemService');
         while ($data = $iterator->next()) {
            if ($data['is_fixed']) {
               $is_scheduleddown = true;
            } else {
               $downtime = new PluginSiemScheduledDowntime();
               $is_scheduleddown = true;
            }
            $is_scheduleddown = true;
            break;
         }
         $is_scheduleddown = false;
      }
      return $is_scheduleddown;
   }

   public function getHost()
   {
      static $host = null;
      if ($host === null) {
         if (static::getType() === 'PluginSiemHost') {
            return $this;
         } else {
            $host = new PluginSiemHost();
            $host->getFromDB($this->fields['plugin_siem_hosts_id']);
         }
      }
      return $host;
   }

   /**
    * Returns the name of this host (or service's host).
    * @since 1.0.0
    */
   public function getHostName()
   {
      global $DB;

      if (static::class === 'PluginSiemHost') {
         $hosttype = $this->fields['itemtype'];
         $iterator = $DB->request([
            'SELECT' => ['name'],
            'FROM' => $hosttype::getTable(),
            'WHERE' => [
               'id' => $this->fields['items_id']
            ]
         ]);
         return $iterator->next()['name'];
      } else {
         if ($this->isHostless()) {
            return '';
         }
         $host = $this->getHost();
         return $host ? $host->getHostName() : null;
      }
   }

   public function getEvents($where = [], $start = 0, $limit = -1)
   {
      global $DB;
      $eventtable = PluginSiemEvent::getTable();
      $servicetable = PluginSiemService::getTable();
      $criteria = [
         'FROM' => PluginSiemEvent::getTable(),
         'LEFT JOIN' => [
            $servicetable => [
               'FKEY' => [
                  $eventtable => 'plugin_siem_services_id',
                  $servicetable => 'id'
               ]
            ]
         ]
      ];
      if (static::getType() === 'SIEMHost') {
         $hosttable = PluginSiemHost::getTable();
         $criteria['LEFT JOIN'][$hosttable] = [
            'FKEY' => [
               $servicetable => 'plugin_siem_hosts_id',
               $hosttable => 'id'
            ]
         ];
         $criteria['WHERE'] = [
            'plugin_siem_hosts_id' => $this->getID()
         ];
      } else {
         $criteria['WHERE'] = [
            'plugin_siem_services_id' => $this->getID()
         ];
      }
      $iterator = $DB->request($criteria);
      $events = [];
      while ($data = $iterator->next()) {
         $events[] = $data;
      }
      return $events;
   }
}