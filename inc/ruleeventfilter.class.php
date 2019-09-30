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


class PluginSIEMRuleEventFilter extends Rule
{

   // From Rule
   static $rightname = 'plugin_siem_rule_event';
   public $can_sort = true;
   const PARENT = 1024;

   const ONADD = 1;

   function getTitle()
   {
      return __('Rules for event filtering');
   }

   function maybeRecursive()
   {
      return true;
   }

   function isEntityAssign()
   {
      return true;
   }

   function canUnrecurs()
   {
      return true;
   }

   function maxActionsCount()
   {
      return 1;
   }

   function addSpecificParamsForPreview($params)
   {
      if (!isset($params["entities_id"])) {
         $params["entities_id"] = $_SESSION["glpiactive_entity"];
      }
      return $params;
   }

   function executeActions($output, $params, array $input = [])
   {
      if (count($this->actions)) {
         foreach ($this->actions as $action) {
            switch ($action->fields["action_type"]) {
               case 'assign':
                  $output[$action->fields["field"]] = $action->fields["value"];
                  break;
            }
         }
      }
      return $output;
   }

   function preProcessPreviewResults($output)
   {
      $output = parent::preProcessPreviewResults($output);
      return Ticket::showPreviewAssignAction($output);
   }

   function getCriterias()
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

      $criterias['entities_id']['table'] = $eventtable;
      $criterias['entities_id']['field'] = 'name';
      $criterias['entities_id']['name'] = __('Entity');
      $criterias['entities_id']['linkfield'] = 'entities_id';
      $criterias['entities_id']['type'] = 'dropdown';

      $criterias['content']['table'] = $eventtable;
      $criterias['content']['field'] = 'content';
      $criterias['content']['name'] = __('Content');
      $criterias['content']['linkfield'] = 'content';

      $criterias['significance']['table'] = $eventtable;
      $criterias['significance']['field'] = 'significance';
      $criterias['significance']['name'] = __('Significance');
      $criterias['significance']['linkfield'] = 'significance';
      $criterias['significance']['type'] = 'dropdown_eventsignificance';

      $criterias['status']['table'] = $eventtable;
      $criterias['status']['field'] = 'status';
      $criterias['status']['name'] = __('Status');
      $criterias['status']['linkfield'] = 'status';
      $criterias['status']['type'] = 'dropdown_eventstatus';

      $criterias['plugins_id']['table'] = $eventtable;
      $criterias['plugins_id']['field'] = 'plugins_id';
      $criterias['plugins_id']['name'] = __('Plugin');
      $criterias['plugins_id']['linkfield'] = 'plugins_id';

      return $criterias;
   }

   static function getConditionsArray()
   {
      return [static::ONADD => __('Add')];
   }

   function getActions()
   {
      $actions = [];
      $actions['accept']['name'] = __('Acceptance');
      $actions['accept']['field'] = '_accept';
      $actions['accept']['type'] = 'yesno';
      $actions['accept']['force_actions'] = ['assign'];

      return $actions;
   }

   function getRights($interface = 'central')
   {
      $values = parent::getRights();
      //TRANS: short for : Business rules for ticket (entity parent)
      $values[self::PARENT] = ['short' => __('Parent business'),
         'long' => __('Rules for event filtering (entity parent)')];

      return $values;
   }
}