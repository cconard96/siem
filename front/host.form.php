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


use Glpi\Event;

include('../../../inc/includes.php');
$host = new PluginSiemHost();
if (isset($_POST['add'])) {
   $host->check(-1, CREATE, $_POST);
   $newID = $host->add($_POST, false);
   Event::log($newID, 'PluginSiemHost', 3, 'tools', 'add');
   Html::back();
} else if (isset($_POST['purge'])) {
   $host->check($_POST['id'], PURGE);
   $host->delete($_POST, 1);
   Event::log($_POST['id'], 'PluginSiemHost', 3, 'tools', 'purge');
   Html::back();
} else if (isset($_POST['update'])) {
   $host->check($_POST['id'], UPDATE);
   $host->update($_POST);
   Event::log($_POST['id'], 'PluginSiemHost', 3, 'tools', 'update');
   Html::back();
} else if (isset($_POST['set_host_service']) && isset($_POST['sensor'])) {
   $host->check($_POST['id'], UPDATE);
   $service = new PluginSiemService();

   $host->update([
      'id' => $_POST['id'],
      'plugin_siem_services_id_availability' => $_POST['sensor']
   ]);
   Event::log($_POST['id'], 'PluginSiemHost', 3, 'tools', 'update');
   Html::back();
} else {
   Html::header(PluginSiemHost::getTypeName(Session::getPluralNumber()), $_SERVER['PHP_SELF'], 'tools', 'siemevent');
   $host->display(['id' => $_GET['id']]);
   Html::footer();
}