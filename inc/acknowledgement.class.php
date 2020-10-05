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


use Symfony\Component\EventDispatcher\EventDispatcher;

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

/**
 * PluginSIEMAcknowledgement class
 * @since 1.0.0
 **/
class PluginSiemAcknowledgement extends CommonDBTM
{

   public static function getTypeName($nb = 0)
   {
      return _n('Acknowledgement', 'Acknowledgements', $nb);
   }

   /**
    *
    * @param PluginSiemMonitored $itemtype
    * @param int $items_id
    * @param string $comment
    * @param array $params
    * @return bool True if the item was acknowledged. False if an error occurred or it is already acknowledged.
    * @since 1.0.0
    */
   public static function acknowledge($itemtype, $items_id, $comment = '', $params = [])
   {
      global $DB;
      $p = [
         'is_sticky' => true,
         'notify' => true
      ];
      $p = array_replace($p, $params);

      if (!($itemtype == 'PluginSiemService') && !($itemtype == 'PluginSiemHost')) {
         // Only SIEMService and SIEMHost are able to be acknowledged
         return false;
      }

      /** @var PluginSiemMonitored|CommonDBTM $item */
      $item = new $itemtype();
      if ($item->isScheduledDown() || !$item->isAlertStatus()) {
         // Cannot acknowledge an item during scheduled downtime
         // Cannot acknowledge if the service/host is not in a problem state
         return false;
      }

      $ack = new self();
      $existing = $ack->find(['itemtype' => $itemtype, 'items_id' => $items_id]);
      if (count($existing) > 0) {
         return false;
      }

      if (!$item->getFromDB($items_id)) {
         throw new RuntimeException("Invalid item {$itemtype} with ID {$items_id}");
      }

      $ack_id = $ack->add([
         'itemtype' => $itemtype,
         'items_id' => $items_id,
         'status' => $item->getStatus(),
         'users_id' => $_SESSION['glpiID'],
         'comment' => $comment,
         'is_sticky' => $p['is_sticky']
      ]);
      if ($ack_id) {
         // Let plugins know the service alert is acknowledged
         $ack->dispatchAcknowledgementEvent($item);
         if ($p['notify']) {
            NotificationEvent::raiseEvent('acknowledge', $item);
         }
      }
   }

   public function getUsername()
   {
      $user = new User();
      $user_name = getUserName($this->fields['users_id']);
      if ($user_name === '') {
         return __('Anonymous');
      }
      return $user_name;
   }

   public function isExpired()
   {
      $expiredate = $this->fields['date_expiration'];
      return ($expiredate !== null && ($expiredate <= $_SESSION['glpi_currenttime']));
   }

   public static function getForHost($host_id, $active = true)
   {
      global $DB, $CFG_GLPI;

      $acktable = self::getTable();
      $hosttable = PluginSiemHost::getTable();

      $criteria = [
         'SELECT' => [
            'is_service',
            'items_id',
            'comment',
            'users_id',
            'is_sticky',
            'date_creation'
         ],
         'FROM' => $acktable,
         'LEFT JOIN' => [
            $hosttable => [
               'FKEY' => [
                  $hosttable => 'id',
                  $acktable => 'items_id'
               ]
            ]
         ],
         'WHERE' => [
            'is_service' => false
         ],
         'ORDERBY' => ['date_creation']
      ];

      if ($active) {
         $criteria['WHERE']['OR'] = [
            'date_expiration' => null,
            new QueryExpression('date_expiration <= NOW()')
         ];
         $criteria['LIMIT'] = 1;
      }

      $iterator = $DB->request($criteria);

      $acknowledgements = [];
      while ($data = $iterator->next()) {
         $acknowledgements[] = $data;
      }

      return $acknowledgements;
   }

   public static function getForService($service_id, $active = true)
   {

   }

   public static function getActivelyAcknowldged()
   {
      global $DB, $CFG_GLPI;

      $iterator = $DB->request([
         'SELECT' => [
            'itemtype',
            'items_id',
            'comment',
            'users_id',
            'is_sticky',
            'date_creation'
         ],
         'FROM' => self::getTable(),
         'WHERE' => [
            'OR' => [
               'date_expiration' => null,
               new QueryExpression('date_expiration <= NOW()')
            ]
         ]
      ]);

      $actively_acknowledged = [];
      while ($data = $iterator->next()) {
         $actively_acknowledged[$data['itemtype']][] = $data['items_id'];
      }

      if (isset($actively_acknowledged['PluginSiemHost'])) {
         // If the host is acknowledged, all services on it are also considered to be acknowledged
         $iterator = $DB->request([
            'SELECT' => ['id'],
            'FROM' => PluginSiemService::getTable(),
            'WHERE' => [
               'plugin_siem_hosts_id' => $actively_acknowledged['PluginSiemHost']
            ]
         ]);
         while ($data = $iterator->next()) {
            $actively_acknowledged['PluginSiemService'][] = $data['id'];
         }
      }
      return $actively_acknowledged;
   }

   private function dispatchAcknowledgementEvent($item)
   {
      global $CONTAINER;

      if (!isset($CONTAINER) || !$CONTAINER->has(EventDispatcher::class)) {
         return;
      }

      $dispatcher = $CONTAINER->get(EventDispatcher::class);

      if ($item->getType() === 'PluginSiemService') {
         $dispatcher->dispatch(SIEMServiceEvent::SERVICE_ACKNOWLEDGE, new SIEMServiceEvent($this, $item));
      } else if ($item->getType() === 'PluginSiemHost') {
         $dispatcher->dispatch(SIEMHostEvent::HOST_ACKNOWLEDGE, new SIEMHostEvent($this, $item));
      }
   }
}