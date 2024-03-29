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

use GlpiPlugin\SIEM\ServiceTemplate;

$AJAX_INCLUDE = 1;
include('../../../inc/includes.php');
header('Content-Type: application/json; charset=UTF-8');
Html::header_nocache();

global $PLUGIN_HOOKS;

$template = new ServiceTemplate();
$templates = $template->find();
$results = [];
foreach ($templates as $result) {
   $results[$result['id']] = $result['name'];
}
echo json_encode($results, JSON_FORCE_OBJECT);