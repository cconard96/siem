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
 * PluginSIEMItil_SIEMEvent Class
 *
 * Relation between SIEMEvents and ITILObjects
 * @since 1.0.0
 **/
class PluginSIEMItil_SIEMEvent extends CommonDBRelation
{

    // From CommonDBRelation
    static public $itemtype_1          = 'SIEMEvent';
    static public $items_id_1          = 'siemevents_id';
    static public $itemtype_2          = 'itemtype';
    static public $items_id_2          = 'items_id';
    static public $checkItem_2_Rights  = self::HAVE_VIEW_RIGHT_ON_ITEM;
    function getForbiddenStandardMassiveAction()
    {
        $forbidden   = parent::getForbiddenStandardMassiveAction();
        $forbidden[] = 'update';
        return $forbidden;
    }
    function canCreateItem()
    {
        $event = new PluginSIEMEvent();
        if ($event->canUpdateItem()) {
            return true;
        }
        return parent::canCreateItem();
    }
    function prepareInputForAdd($input)
    {
        // Avoid duplicate entry
        if (countElementsInTable($this->getTable(), ['siemevents_id' => $input['siemevents_id'],
                'itemtype'   => $input['itemtype'],
                'items_id'   => $input['items_id']]) > 0) {
            return false;
        }
        return parent::prepareInputForAdd($input);
    }
    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$withtemplate) {
            $nb = 0;
            switch ($item->getType()) {
                case Change::class :
                case Problem::class :
                case Ticket::class :
                    if ($_SESSION['glpishow_count_on_tabs']) {
                        $nb = countElementsInTable(
                            self::getTable(),
                            [
                                'itemtype' => $item->getType(),
                                'items_id' => $item->getID(),
                            ]
                        );
                    }
                    return self::createTabEntry(PluginSIEMEvent::getTypeName(Session::getPluralNumber()), $nb);
                    break;
                case 'SIEMEvent' :
                    if ($_SESSION['glpishow_count_on_tabs']) {
                        $nb = countElementsInTable(self::getTable(), ['plugin_siem_events_id' => $item->getID()]);
                    }
                    return self::createTabEntry(_n('Itil item', 'Itil items', Session::getPluralNumber()), $nb);
            }
        }
        return '';
    }
    static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        switch ($item->getType()) {
            case 'PluginSIEMEvent' :
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
     * @param $withtemplate    withtemplate param (default 0)
     **/
    static function showForItil(CommonDBTM $item, $withtemplate = 0)
    {
        PluginSIEMEvent::showListForItil(false, $item);
    }
}