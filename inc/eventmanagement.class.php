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

namespace GlpiPlugin\SIEM;

use CommonGLPI;
use Session;

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

/**
 * PluginSIEMEventManagement class.
 * Contains functions for managing/viewing the dashboard and other top-level functions.
 * @since 1.0.0
 */
class EventManagement extends CommonGLPI
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
      return Host::canView() || Service::canView();
   }

   public static function getDashboardCards(): array
   {
      $cards = [];

      $cards['plugin_siem_monitored_summary'] = [
         'widgettype'  => ['summaryNumbers', 'multipleNumber'],
         'label'       => __('Monitored Count'),
         'provider'    => __CLASS__ .'::cardMonitoredCountProvider'
      ];
      $cards['plugin_siem_host_count'] = [
         'widgettype'  => ['bigNumber'],
         'label'       => __('Monitored Host Count'),
         'provider'    => __CLASS__ .'::cardHostCountProvider'
      ];
      $cards['plugin_siem_service_count'] = [
         'widgettype'  => ['bigNumber'],
         'label'       => __('Monitored Services Count'),
         'provider'    => __CLASS__ .'cardServiceCountProvider'
      ];
      $cards['plugin_siem_service_status'] = [
         'widgettype'   => ['pie', 'donut', 'halfpie', 'halfdonut', 'summaryNumbers', 'multipleNumber', 'bar', 'hbar'],
         'label'        => __('Service Status'),
         'provider'     => __CLASS__ .'::cardServiceStatusProvider'
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
         'FROM'  => Host::getTable(),
      ]);
      $host_count = $iterator->next()['cpt'];
      $iterator = $DB->request([
         'SELECT'   => [
            'COUNT' => 'id as cpt'
         ],
         'FROM'  => Service::getTable(),
      ]);
      $service_count = $iterator->next()['cpt'];

      return [
         'data'   => [
            [
               'label'  => Host::getTypeName(Session::getPluralNumber()),
               'number' => $host_count
            ],
            [
               'label'  => Service::getTypeName(Session::getPluralNumber()),
               'number' => $service_count
            ]
         ]
      ];
   }

   public static function cardHostCountProvider()
   {
      global $DB;

      $table = Host::getTable();
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

      $table = Service::getTable();
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
         'FROM'  => Service::getTable()
      ]);

      $status_counts = [];

      while ($data = $iterator->next()) {
         $status_counts[$data['status']] = $data['cpt'];
      }

      $statuses = [Service::STATUS_OK, Service::STATUS_WARNING, Service::STATUS_CRITICAL, Service::STATUS_UNKNOWN];
      $card = [
         'label'  => __('Service Status'),
         'data'   => []
      ];

      foreach ($statuses as $status) {
         $card['data'][] = [
            'label'  => Service::getStatusName($status),
            'number' => $status_counts[$status] ?? 0,
            'url'    => Service::getSearchURL() . '?' . Toolbox::append_params([
               'criteria'  => [
                  [
                     'field'        => 5,
                     'searchtype'   => 'equals',
                     'value'        => $status
                  ]
               ],
               'reset'     => 'reset'
            ])
         ];
      }
      return $card;
   }
}