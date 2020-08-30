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


define('PLUGIN_SIEM_VERSION', '1.0.0');
define('PLUGIN_SIEM_MIN_GLPI', '9.5.0');
define('PLUGIN_SIEM_MAX_GLPI', '9.6.0');

function plugin_init_siem()
{
   global $PLUGIN_HOOKS;
   $PLUGIN_HOOKS['csrf_compliant']['siem'] = true;
   $PLUGIN_HOOKS['add_css']['siem'] = 'css/siem.css';
   $PLUGIN_HOOKS['add_javascript']['siem'] = 'js/siem.js';
   Plugin::registerClass('PluginSiemProfile', ['addtabon' => ['Profile']]);
   Plugin::registerClass('PluginSiemEvent', ['addtabon' => [
      'Computer', 'Printer', 'NetworkEquipment', 'Phone', 'User', 'Group', 'Enclosure', 'PDU'
   ]]);
   if (Session::haveRight('plugin_siem_host', READ)) {
      $PLUGIN_HOOKS['menu_toadd']['siem'] = ['management' => [
         'PluginSiemMenu',
         'PluginSiemHost',
         'PluginSiemService',
         'PluginSiemServiceTemplate'
      ]];
   }
   $PLUGIN_HOOKS['siem_sensors']['siem'] = [
      'ping' => [
         'name'         => __('Ping'),
         'check_mode'   => PluginSiemService::CHECK_MODE_ACTIVE,
      ],
      'http_ok' => [
         'name'         => __('HTTP OK'),
         'check_mode'   => PluginSiemService::CHECK_MODE_ACTIVE,
      ]
   ];
}

function plugin_version_siem()
{

   return [
      'name' => __("SIEM Plugin for GLPI", 'siem'),
      'version' => PLUGIN_SIEM_VERSION,
      'author' => 'Curtis Conard',
      'license' => 'GPLv2',
      'homepage' => 'https://github.com/cconard96/siem',
      'requirements' => [
         'glpi' => [
            'min' => PLUGIN_SIEM_MIN_GLPI,
            'max' => PLUGIN_SIEM_MAX_GLPI
         ]
      ]
   ];
}

function plugin_siem_check_prerequisites()
{
   if (!method_exists('Plugin', 'checkGlpiVersion')) {
      $version = preg_replace('/^((\d+\.?)+).*$/', '$1', GLPI_VERSION);
      $matchMinGlpiReq = version_compare($version, PLUGIN_SIEM_MIN_GLPI, '>=');
      $matchMaxGlpiReq = version_compare($version, PLUGIN_SIEM_MAX_GLPI, '<');
      if (!$matchMinGlpiReq || !$matchMaxGlpiReq) {
         echo vsprintf(
            'This plugin requires GLPI >= %1$s and < %2$s.',
            [
               PLUGIN_SIEM_MIN_GLPI,
               PLUGIN_SIEM_MAX_GLPI,
            ]
         );
         return false;
      }
   }
   return true;
}

function plugin_siem_check_config()
{
   return true;
}