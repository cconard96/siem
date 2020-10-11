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

/**
 * PluginSIEMEventManagement class.
 * Contains functions for managing/viewing the dashboard and other top-level functions.
 * @since 1.0.0
 */
class PluginSiemEventManagement extends CommonGLPI
{

   public static function getTypeName($nb = 0)
   {
      return __('Event Dashboard');
   }

   public static function getMenuName()
   {
      return self::getTypeName(0);
   }

   public static function getIcon() {
      return 'fas fa-shield-alt';
   }

   /**
    * Check if can view item
    *
    * @return boolean
    */
   public static function canView() {
      return PluginSiemHost::canView() || PluginSiemService::canView();
   }

   public static function getDashboardCards(): array
   {
      $cards = [];

      $cards['plugin_siem_monitored_summary'] = [
         'widgettype'  => ['summaryNumbers', 'multipleNumber'],
         'label'       => __('Monitored Count'),
         'provider'    => 'PluginSiemEventManagement::cardMonitoredCountProvider'
      ];
      $cards['plugin_siem_host_count'] = [
         'widgettype'  => ['bigNumber'],
         'label'       => __('Monitored Host Count'),
         'provider'    => 'PluginSiemEventManagement::cardHostCountProvider'
      ];
      $cards['plugin_siem_service_count'] = [
         'widgettype'  => ['bigNumber'],
         'label'       => __('Monitored Services Count'),
         'provider'    => 'PluginSiemEventManagement::cardServiceCountProvider'
      ];
      $cards['plugin_siem_service_status'] = [
         'widgettype'   => ['pie', 'donut', 'halfpie', 'halfdonut', 'summaryNumbers', 'multipleNumber', 'bar', 'hbar'],
         'label'        => __('Service Status'),
         'provider'     => 'PluginSiemEventManagement::cardServiceStatusProvider'
      ];

      return $cards;
   }

   public static function cardMonitoredCountProvider()
   {
      global $DB;

      $iterator = $DB->request([
         'SELECT'   => [
            'COUNT' => 'id as cpt'
         ],
         'FROM'  => PluginSiemHost::getTable(),
      ]);
      $host_count = $iterator->next()['cpt'];
      $iterator = $DB->request([
         'SELECT'   => [
            'COUNT' => 'id as cpt'
         ],
         'FROM'  => PluginSiemService::getTable(),
      ]);
      $service_count = $iterator->next()['cpt'];

      return [
         'data'   => [
            [
               'label'  => PluginSiemHost::getTypeName(Session::getPluralNumber()),
               'number' => $host_count
            ],
            [
               'label'  => PluginSiemService::getTypeName(Session::getPluralNumber()),
               'number' => $service_count
            ]
         ]
      ];
   }

   public static function cardHostCountProvider()
   {
      global $DB;

      $table = PluginSiemHost::getTable();
      $iterator = $DB->request([
         'SELECT'   => [
            'COUNT' => 'id as cpt'
         ],
         'FROM'  => $table,
      ]);

      return [
         'label' => __('Monitored Host Count'),
         'number' => $iterator->next()['cpt']
      ];
   }

   public static function cardServiceCountProvider()
   {
      global $DB;

      $table = PluginSiemService::getTable();
      $iterator = $DB->request([
         'SELECT'   => [
            'COUNT' => 'id as cpt'
         ],
         'FROM'  => $table,
      ]);

      return [
         'label' => __('Monitored Service Count'),
         'number' => $iterator->next()['cpt']
      ];
   }

   public static function cardServiceStatusProvider()
   {
      global $DB;

      $iterator = $DB->request([
         'SELECT'   => [
            'COUNT'  => 'id as cpt',
            'status'
         ],
         'FROM'  => PluginSiemService::getTable()
      ]);

      $status_counts = [];

      while ($data = $iterator->next()) {
         $status_counts[$data['status']] = $data['cpt'];
      }

      return [
         'label'  => __('Service Status'),
         'data'   => [
            [
               'label'  => PluginSiemService::getStatusName(PluginSiemService::STATUS_OK),
               'number' => $status_counts[PluginSiemService::STATUS_OK] ?? 0
            ],
            [
               'label'  => PluginSiemService::getStatusName(PluginSiemService::STATUS_WARNING),
               'number' => $status_counts[PluginSiemService::STATUS_WARNING] ?? 0
            ],
            [
               'label'  => PluginSiemService::getStatusName(PluginSiemService::STATUS_CRITICAL),
               'number' => $status_counts[PluginSiemService::STATUS_CRITICAL] ?? 0
            ],
            [
               'label'  => PluginSiemService::getStatusName(PluginSiemService::STATUS_UNKNOWN),
               'number' => $status_counts[PluginSiemService::STATUS_UNKNOWN] ?? 0
            ]
         ]
      ];
   }
}