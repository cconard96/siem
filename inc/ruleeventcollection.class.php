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

class PluginSIEMRuleEventCollection extends RuleCollection
{

   // From RuleCollection
   public static $rightname = 'rule_event';
   public $stop_on_first_match = true;
   public $menu_option = 'plugin_siem_rulesevent';


   public function __construct($entity = 0)
   {
      parent::__construct();
      $this->entity = $entity;
   }

   public static function canView()
   {
      return Session::haveRightsOr(self::$rightname, [READ, PluginSIEMRuleEvent::PARENT]);
   }

   public function canList()
   {
      return static::canView();
   }

   public function getTitle()
   {
      return __('Business rules for events');
   }

   public function showInheritedTab()
   {
      return (Session::haveRight(self::$rightname, PluginSIEMRuleEvent::PARENT) && ($this->entity));
   }

   public function showChildrensTab()
   {
      return (Session::haveRight(self::$rightname, READ)
         && (count($_SESSION['glpiactiveentities']) > 1));
   }
}