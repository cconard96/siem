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
   die("Sorry. You can't access directly to this file");
}

/**
 * PluginSIEMItil_ScheduledDowntime Class
 *
 * Relation between SIEMEvents and ITILObjects
 * @since 1.0.0
 **/
class PluginSIEMItil_ScheduledDowntime extends CommonDBRelation
{

   // From CommonDBRelation
   static public $itemtype_1 = 'ScheduledDowntime';
   static public $items_id_1 = 'scheduleddowntimes_id';
   static public $itemtype_2 = 'itemtype';
   static public $items_id_2 = 'items_id';
   static public $checkItem_2_Rights = self::HAVE_VIEW_RIGHT_ON_ITEM;

   public function getForbiddenStandardMassiveAction()
   {
      $forbidden = parent::getForbiddenStandardMassiveAction();
      $forbidden[] = 'update';
      return $forbidden;
   }

   public function canCreateItem()
   {
      $downtime = new PluginSiemScheduledDowntime();
      if ($downtime->canUpdateItem()) {
         return true;
      }
      return parent::canCreateItem();
   }

   public function post_addItem()
   {
      $downtime = new PluginSiemScheduledDowntime();
      $input = [
         'id' => $this->fields[self::$items_id_1],
         'date_mod' => $_SESSION['glpi_currenttime'],
      ];
      $downtime->update($input);
      parent::post_addItem();
   }

   public function post_purgeItem()
   {
      $downtime = new PluginSiemScheduledDowntime();
      $input = [
         'id' => $this->fields[self::$items_id_1],
         'date_mod' => $_SESSION['glpi_currenttime'],
      ];
      $downtime->update($input);
      parent::post_purgeItem();
   }

   public function prepareInputForAdd($input)
   {
      // Avoid duplicate entry
      if (countElementsInTable($this->getTable(), [self::$items_id_1 => $input[self::$items_id_1],
            self::$itemtype_2 => $input[self::$itemtype_2],
            self::$items_id_2 => $input[self::$items_id_2]]) > 0) {
         return false;
      }
      return parent::prepareInputForAdd($input);
   }

   /**
    * Display events for an item
    *
    * @param $item            CommonDBTM object for which the event tab need to be displayed
    * @param int $withtemplate withtemplate param (default 0)
    */
   static function showForItil(CommonDBTM $item, $withtemplate = 0)
   {
      PluginSiemScheduledDowntime::showListForItil(false, $item);
   }
}