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

if (strpos($_SERVER['PHP_SELF'], 'dropdownSIEMSensors.php')) {
   $AJAX_INCLUDE = 1;
   include('../../../inc/includes.php');
   header('Content-Type: text/html; charset=UTF-8');
   Html::header_nocache();
}
Session::checkRight('event', UPDATE);
global $PLUGIN_HOOKS;
if ($_POST['plugins_id'] > 0) {
   if (!isset($_POST['value'])) {
      $_POST['value'] = 0;
   }
   $values = [];
   $plugin = Plugin::getPlugins()[$_POST['plugins_id']];
   if ($plugin && isset($PLUGIN_HOOKS['siem_sensors'][$plugin])) {
      $sensors = $PLUGIN_HOOKS['siem_sensors'][$plugin];
      foreach ($sensors as $sensor_id => $params) {
         $values[$sensor_id] = $params['name'];
      }
   }
   Dropdown::showFromArray($_POST['myname'], $values, ['display_emptychoice' => true]);
}