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
header('Content-Type: text/html; charset=UTF-8');
Html::header_nocache();
Session::checkLoginUser();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
   // Get AJAX input and load it into $_REQUEST
   $input = file_get_contents('php://input');
   parse_str($input, $_REQUEST);
}

if (!isset($_REQUEST['hosts_id'])) {
   return false;
}
$host = new PluginSiemHost();
if (!$host->getFromDB($_REQUEST['hosts_id'])) {
   return false;
}
if (isset($_REQUEST['_schedule_downtime'])) {

} else if (isset($_REQUEST['_check_now'])) {
   $host->checkNow();
} else if (isset($_REQUEST['_add_service'])) {
   if (!isset($_REQUEST['hosts_id'], $_REQUEST['servicetemplates_id'])) {
      http_response_code(400);
      return;
   }
   $service = new PluginSiemService();
   $match = $service->find([
      'plugin_siem_hosts_id' => $_REQUEST['hosts_id'],
      'plugin_siem_servicetemplates_id' => $_POST['servicetemplates_id']
   ]);
   if (!count($match)) {
      $service->add([
         'plugin_siem_hosts_id' => $_REQUEST['hosts_id'],
         'plugin_siem_servicetemplates_id' => $_REQUEST['servicetemplates_id']
      ]);
      http_response_code(201);
   } else {
      http_response_code(202);
   }
}