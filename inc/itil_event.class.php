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

namespace GlpiPlugin\SIEM;

use Change;
use CommonDBRelation;
use CommonDBTM;
use CommonGLPI;
use Problem;
use Session;
use Ticket;

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access directly to this file");
}

/**
 * PluginSIEMItil_SIEMEvent Class
 *
 * Relation between PluginSIEMEvents and ITILObjects
 * @since 1.0.0
 **/
class Itil_Event extends CommonDBRelation
{

   // From CommonDBRelation
   static public $itemtype_1 = Event::class;
   static public $items_id_1 = 'plugin_siem_events_id';
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
      $event = new Event();
      if ($event->canUpdateItem()) {
         return true;
      }
      return parent::canCreateItem();
   }

   public function prepareInputForAdd($input)
   {
      // Avoid duplicate entry
      $event_fk = Event::getForeignKeyField();
      if (countElementsInTable(self::getTable(), [$event_fk => $input[$event_fk],
            'itemtype' => $input['itemtype'],
            'items_id' => $input['items_id']]) > 0) {
         return false;
      }
      return parent::prepareInputForAdd($input);
   }

   public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
   {
      if (!$withtemplate) {
         $nb = 0;
         switch ($item->getType()) {
            case Change::class:
            case Problem::class:
            case Ticket::class:
               if ($_SESSION['glpishow_count_on_tabs']) {
                  $nb = countElementsInTable(
                     self::getTable(),
                     [
                        'itemtype' => $item->getType(),
                        'items_id' => $item->getID(),
                     ]
                  );
               }
               return self::createTabEntry(Event::getTypeName(Session::getPluralNumber()), $nb);
               break;
            case Event::class:
               if ($_SESSION['glpishow_count_on_tabs']) {
                  $nb = countElementsInTable(self::getTable(), [Event::getForeignKeyField() => $item->getID()]);
               }
               return self::createTabEntry(_n('Itil item', 'Itil items', Session::getPluralNumber()), $nb);
         }
      }
      return '';
   }

   public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
   {
      switch ($item->getType()) {
         case Event::class :
            self::showForSIEMEvent($item);
            break;
         default:
            self::showForItil($item);
            break;
      }
      return true;
   }

   /**
    * Display events for an item
    *
    * @param $item            CommonDBTM object for which the event tab need to be displayed
    * @param int $withtemplate withtemplate param (default 0)
    */
   public static function showForItil(CommonDBTM $item, $withtemplate = 0)
   {
      Event::showListForItil(false, $item);
   }
}