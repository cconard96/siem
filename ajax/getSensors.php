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


$AJAX_INCLUDE = 1;
include('../../../inc/includes.php');
header('Content-Type: application/json; charset=UTF-8');
Html::header_nocache();

global $PLUGIN_HOOKS;

if (isset($_GET['plugins_id'])) {
   if ((int) $_GET['plugins_id'] === 0) {
      // GLPI Core
      // No internal sensors yet so return empty array
      echo '{}';
   } else {
      $plugin = new Plugin();
      $plugin->getFromDB($_GET['plugins_id']);
      $pluginname = $plugin->fields['directory'];
      if (array_key_exists('siem_sensors', $PLUGIN_HOOKS) &&
         array_key_exists($pluginname, $PLUGIN_HOOKS['siem_sensors'])) {
         $sensors = $PLUGIN_HOOKS['siem_sensors'][$pluginname];
         $values = [];
         foreach ($sensors as $id => $params) {
            $values[$id] = $params['name'];
         }
         echo json_encode($values, JSON_FORCE_OBJECT);
      }
   }
} else {
   http_response_code(400);
}