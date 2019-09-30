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


/**
 * ScheduledDowntime class.
 * This represents a period of time when a host or service will be down and all alerts during that time can be ignored.
 *
 * @since 1.0.0
 */
class PluginSiemScheduledDowntime extends CommonDBTM
{

   /**
    * Name of the type
    *
    * @param $nb : number of item in the type
    * @return string
    **/
   static function getTypeName($nb = 0)
   {
      return _n('Scheduled Downtime', 'Scheduled Downtimes', $nb);
   }

   public static function getForHostOrService($items_id, $is_service = true, $params = [])
   {
      global $DB;

      $p = [
         'start' => $_SESSION['glpi_currenttime'],
         'end' => $_SESSION['glpi_currenttime']
      ];
      $p = array_replace($p, $params);

      $downtimetable = self::getTable();
      $monitoredtable = $is_service ? PluginSiemService::getTable() : PluginSiemHost::getTable();

      $where = [
         "$downtimetable.items_id_target" => $items_id,
         "$downtimetable.is_service" => $is_service
      ];

      if (!is_null($p['start'])) {
         $where[] = new QueryExpression("'{$p['start']}' >= begin_date");
      }
      if (!is_null($p['end'])) {
         $where[] = new QueryExpression("'{$p['end']}' <= end_date");
      }

      $iterator = $DB->request([
         'FROM' => $downtimetable,
         'LEFT JOIN' => [
            $monitoredtable => [
               'FKEY' => [
                  $monitoredtable => 'id',
                  $downtimetable => 'items_id_target'
               ]
            ]
         ],
         'WHERE' => $where
      ]);

      return $iterator;
   }

   public static function getActivelyDown()
   {
      global $DB;

      $iterator = $DB->request([
         'SELECT' => ['is_service', 'items_id'],
         'FROM' => PluginSiemScheduledDowntime::getTable(),
         'WHERE' => [
            new QueryExpression("begin_date <= NOW()"),
            new QueryExpression("end_date >= NOW()")
         ]
      ]);

      $actively_down = [];
      while ($data = $iterator->next()) {
         $type = $data['is_service'] ? 'SIEMService' : 'SIEMHost';
         $actively_down[$type][] = $data['items_id'];
      }

      if (isset($actively_down['SIEMHost'])) {
         // If the host is scheduled down, all services on it are also considered to be scheduled down
         $iterator = $DB->request([
            'SELECT' => ['id'],
            'FROM' => PluginSiemService::getTable(),
            'WHERE' => [
               'siemhosts_id' => $actively_down['SIEMHost']
            ]
         ]);
         while ($data = $iterator->next()) {
            $actively_down['SIEMService'][] = $data['id'];
         }
      }
      return $actively_down;
   }

   public function prepareInputForUpdate($input)
   {
      if (isset($input['_cancel'])) {
         $input['end_date'] = $_SESSION['glpi_currenttime'];
      }
   }

   public function post_updateItem($history = 1)
   {
      if (isset($this->input['_cancel'])) {
         $this->dispatchScheduledDowntimeEvent('scheduleddowntime.cancel');
      }
   }

   private function dispatchScheduledDowntimeEvent($eventName)
   {
      global $CONTAINER;

      if (!isset($CONTAINER) || !$CONTAINER->has(EventDispatcher::class)) {
         return;
      }

      $dispatcher = $CONTAINER->get(EventDispatcher::class);
      $dispatcher->dispatch($eventName, new ScheduledDowntimeEvent($this));
   }
}