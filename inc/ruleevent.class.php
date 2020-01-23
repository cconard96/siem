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


class PluginSIEMRuleEvent extends Rule
{

   // From Rule
   static $rightname = 'rule_event';
   public $can_sort = true;
   const PARENT = 1024;

   const ONADD = 1;

   public function getTitle()
   {
      return __('Business rules for events');
   }


   public function maybeRecursive()
   {
      return true;
   }

   public function isEntityAssign()
   {
      return true;
   }

   public function canUnrecurs()
   {
      return true;
   }

   public function addSpecificParamsForPreview($params)
   {

      if (!isset($params['entities_id'])) {
         $params['entities_id'] = $_SESSION['glpiactive_entity'];
      }
      return $params;
   }

   public function executeActions($output, $params, array $input = [])
   {
      if (count($this->actions)) {
         $siemevent = new PluginSiemEvent();
         if (!$siemevent->getFromDB($output['id'])) {
            return $output;
         }
         foreach ($this->actions as $action) {
            switch ($action->fields['action_type']) {
               case 'assign_correlated' :
                  // Set field of all events correlated with this one (Example: Resolve all)
                  $siemevent->updateCorrelated([$action->fields['field'] => $action->fields['value']]);
                  break;
            }
         }
         //Ensure notification and tracking actions are run last
         foreach ($this->actions as $action) {
            switch ($action->fields['action_type']) {
               case 'send' :
               case 'send_email' :
                  NotificationEvent::raiseEvent('new', $siemevent);
                  break;

               case 'create_ticket' :
                  $siemevent->createTracking('Ticket');
                  break;

               case 'create_change' :
                  $siemevent->createTracking('Change');
                  break;

               case 'create_problem' :
                  $siemevent->createTracking('Problem');
                  break;
            }
         }
      }
      return $output;
   }

   public function getCriterias()
   {
      static $criterias = [];

      if (count($criterias)) {
         return $criterias;
      }

      $eventtable = PluginSiemEvent::getTable();

      $criterias['name']['table'] = $eventtable;
      $criterias['name']['field'] = 'name';
      $criterias['name']['name'] = __('Name');
      $criterias['name']['linkfield'] = 'name';

      $criterias['content']['table'] = $eventtable;
      $criterias['content']['field'] = 'content';
      $criterias['content']['name'] = __('Content');
      $criterias['content']['linkfield'] = 'content';

      $criterias['significance']['table'] = $eventtable;
      $criterias['significance']['field'] = 'significance';
      $criterias['significance']['name'] = __('Significance');
      $criterias['significance']['type'] = 'dropdown_eventsignificance';
      $criterias['significance']['linkfield'] = 'significance';

      $criterias['status']['table'] = $eventtable;
      $criterias['status']['field'] = 'status';
      $criterias['status']['name'] = __('Status');
      $criterias['status']['type'] = 'dropdown_eventstatus';
      $criterias['status']['linkfield'] = 'status';

      return $criterias;
   }

   public function checkCriteria(&$criteria, &$input)
   {
      switch ($criteria) {
         default:
            return parent::checkCriteria($criteria, $input);
      }
   }

   public static function getConditionsArray()
   {
      return [static::ONADD => __('Add')];
   }

   public function getActions()
   {
      $actions = [];

      $actions['_ticket']['name'] = __('Create ticket');
      $actions['_ticket']['type'] = 'yesonly';
      $actions['_ticket']['force_actions'] = ['create_ticket'];

      $actions['_change']['name'] = __('Create change');
      $actions['_change']['type'] = 'yesonly';
      $actions['_change']['force_actions'] = ['create_change'];

      $actions['_problem']['name'] = __('Create problem');
      $actions['_problem']['type'] = 'yesonly';
      $actions['_problem']['force_actions'] = ['create_problem'];

      $actions['users_id_email']['name'] = __('Send email alert to user');
      $actions['users_id_email']['type'] = 'dropdown_users';
      $actions['users_id_email']['force_actions'] = ['send_email'];
      $actions['users_id_email']['permitseveral'] = ['send_email'];

      $actions['group_id_email']['name'] = __('Send email alert to group');
      $actions['group_id_email']['type'] = 'dropdown_groups';
      $actions['group_id_email']['force_actions'] = ['send_email'];
      $actions['group_id_email']['permitseveral'] = ['send_email'];

      $actions['name']['name'] = __('Name');
      $actions['name']['linkfield'] = 'name';
      $actions['name']['table'] = self::getTable();
      $actions['name']['force_actions'] = ['assign', 'assign_correlated'];

      $actions['significance']['name'] = __('Significance');
      $actions['significance']['type'] = 'dropdown_eventsignificance';
      $actions['significance']['table'] = self::getTable();
      $actions['significance']['force_actions'] = ['assign', 'assign_correlated'];

      $actions['status']['name'] = __('Status');
      $actions['status']['type'] = 'dropdown_eventstatus';
      $actions['status']['force_actions'] = ['assign', 'assign_correlated'];

      return $actions;
   }

   public function getRights($interface = 'central')
   {

      $values = parent::getRights();
      $values[self::PARENT] = ['short' => __('Parent business'),
         'long' => __('Business rules for event (entity parent)')];

      return $values;
   }
}