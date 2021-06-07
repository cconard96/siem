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

use GlpiPlugin\SIEM\Event;
use GlpiPlugin\SIEM\EventManagement;
use GlpiPlugin\SIEM\Service;
use GlpiPlugin\SIEM\ServiceTemplate;

define('PLUGIN_SIEM_VERSION', '1.0.0-alpha-1');
define('PLUGIN_SIEM_MIN_GLPI', '10.0.0');
define('PLUGIN_SIEM_MAX_GLPI', '11.0.0');

function plugin_init_siem()
{
   global $PLUGIN_HOOKS, $CFG_GLPI;
   $PLUGIN_HOOKS['csrf_compliant']['siem'] = true;
   if (!Plugin::isPluginActive('siem')) {
      return false;
   }
   require_once 'vendor/autoload.php';
   $PLUGIN_HOOKS['add_css']['siem'] = ['node_modules/jquery-ui-dist/jquery-ui.min.css', 'css/siem.css'];
   $PLUGIN_HOOKS['add_javascript']['siem'] = ['node_modules/jquery-ui-dist/jquery-ui.min.js'];
   $PLUGIN_HOOKS['add_javascript']['siem'][] = 'js/siem.js';
   Plugin::registerClass(\GlpiPlugin\SIEM\Profile::class, ['addtabon' => ['Profile']]);
   Plugin::registerClass(Event::class, ['addtabon' => $CFG_GLPI["networkport_types"]]);
   if (Session::haveRight('plugin_siem_host', READ)) {
      $PLUGIN_HOOKS['menu_toadd']['siem'] = ['management' => [
         Service::class,
         ServiceTemplate::class,
//         'PluginSiemAcknowledgement',
//         'PluginSiemScheduleddowntime',
      ]];
   }
   $PLUGIN_HOOKS['siem_sensors']['siem'] = [
      'ping' => [
         'name'         => __('Ping'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'http' => [
         'name'         => __('HTTP OK'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_inv_volume' => [
         'name'         => __('Volume free space (GLPI Inventory)', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_cas' => [
         'name'         => __('GLPI CAS', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_crontask' => [
         'name'         => __('GLPI Cron Tasks', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_db' => [
         'name'         => __('GLPI Database', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_filesystem' => [
         'name'         => __('GLPI File System', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_imap' => [
         'name'         => __('GLPI IMAP', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_ldap' => [
         'name'         => __('GLPI LDAP', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_mailcollector' => [
         'name'         => __('GLPI Mail Collector', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
      'glpi_plugin' => [
         'name'         => __('GLPI Plugins', 'siem'),
         'check_mode'   => Service::CHECK_MODE_ACTIVE,
      ],
   ];
   $PLUGIN_HOOKS['dashboard_cards']['siem'] = [EventManagement::class, 'getDashboardCards'];
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
   if (!is_readable(__DIR__ . '/vendor/autoload.php') || !is_file(__DIR__ . '/vendor/autoload.php')) {
      echo "Run composer install --no-dev in the plugin directory<br>";
      return false;
   }
   return true;
}

function plugin_siem_check_config()
{
   return true;
}
