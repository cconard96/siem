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

include(dirname(__FILE__) . '/inc/sensors/sensor.class.php');
include(dirname(__FILE__) . '/inc/sensors/ping.php');
include(dirname(__FILE__) . '/inc/sensors/http_ok.php');

function plugin_siem_install()
{
   global $DB;

   $migration = new Migration(PLUGIN_SIEM_VERSION);

   if (!$DB->tableExists('glpi_plugin_siem_events')) {
      $query = "CREATE TABLE `glpi_plugin_siem_events` (
         `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
         `name` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
         `status` tinyint(4) NOT NULL DEFAULT '0',
         `date` datetime DEFAULT NULL,
         `content` longtext COLLATE utf8_unicode_ci,
         `date_creation` datetime DEFAULT NULL,
         `significance` tinyint(4) NOT NULL,
         `correlation_id` VARCHAR(23) DEFAULT NULL,
         `date_mod` datetime DEFAULT NULL,
         `plugin_siem_services_id` int(11) NOT NULL,
         PRIMARY KEY (`id`),
         KEY `name` (`name`),
         KEY `status` (`status`),
         KEY `date` (`date`),
         KEY `date_creation` (`date_creation`),
         KEY `significance` (`significance`),
         KEY `correlation_id` (`correlation_id`),
         KEY `plugin_siem_services_id` (`plugin_siem_services_id`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_events");
   }
   if (!$DB->tableExists('glpi_plugin_siem_itils_events')) {
      $query = "CREATE TABLE `glpi_plugin_siem_itils_events` (
         `id` int(11) NOT NULL AUTO_INCREMENT,
         `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
         `items_id` int(11) NOT NULL DEFAULT '0',
         `plugin_siem_events_id` int(11) unsigned NOT NULL DEFAULT '0',
         PRIMARY KEY (`id`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_itils_events");
   }
   if (!$DB->tableExists('glpi_plugin_siem_hosts')) {
      $query = "CREATE TABLE `glpi_plugin_siem_hosts` (
      `id` int(11) NOT NULL,
      `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
      `items_id` int(11) NOT NULL,
      `plugin_siem_services_id_availability` int(11) DEFAULT NULL,
      `is_reachable` tinyint(1) NOT NULL DEFAULT '1',
      `date_mod` timestamp NULL DEFAULT NULL,
      `date_creation` timestamp NULL DEFAULT NULL,
      PRIMARY KEY (`id`),
      KEY `item` (`items_id`,`itemtype`)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_hosts");
   }
   if (!$DB->tableExists('glpi_plugin_siem_services')) {
      $query = "CREATE TABLE `glpi_plugin_siem_services` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `plugin_siem_hosts_id` int(11) NOT NULL DEFAULT -1,
      `plugin_siem_servicetemplates_id` int(11) NOT NULL,
      `last_check` timestamp NULL DEFAULT NULL,
      `status` tinyint(3) NOT NULL DEFAULT '2',
      `is_hard_status` tinyint(1) NOT NULL DEFAULT '1',
      `status_since` timestamp NULL DEFAULT NULL,
      `is_flapping` tinyint(1) NOT NULL DEFAULT '0',
      `is_active` tinyint(1) NOT NULL DEFAULT '1',
      `flap_state_cache` longtext COLLATE utf8_unicode_ci,
      `current_check` int(11) NOT NULL DEFAULT '0',
      `suppress_informational` tinyint(1) NOT NULL DEFAULT '0',
      `is_acknowledged` tinyint(1) NOT NULL DEFAULT '0',
      `date_mod` timestamp NULL DEFAULT NULL,
      `date_creation` timestamp NULL DEFAULT NULL,
      PRIMARY KEY (`id`),
      KEY `plugin_siem_servicetemplates_id` (`plugin_siem_servicetemplates_id`),
      KEY `plugin_siem_hosts_id` (`plugin_siem_hosts_id`),
      KEY `is_flapping` (`is_flapping`),
      KEY `is_acknowledged` (`is_acknowledged`)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_services");
   }
   if (!$DB->tableExists('glpi_plugin_siem_servicetemplates')) {
      $query = "CREATE TABLE `glpi_plugin_siem_servicetemplates` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `name` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
      `comment` text COLLATE utf8_unicode_ci DEFAULT NULL,
      `priority` tinyint(3) NOT NULL DEFAULT 3,
      `calendars_id` int(11) DEFAULT NULL,
      `notificationinterval` int(11) DEFAULT NULL,
      `check_interval` int(11) DEFAULT NULL COMMENT 'Ignored when check_mode is passive',
      `use_flap_detection` tinyint(1) NOT NULL DEFAULT '0',
      `check_mode` tinyint(3) NOT NULL DEFAULT '0',
      `logger` varchar(255)  COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Indicates which plugin (or the core) logged this event. Used to delegate translations and other functions',
      `sensor` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
      `is_stateless` tinyint(1) NOT NULL DEFAULT '0',
      `flap_threshold_low` tinyint(3) NOT NULL DEFAULT '15',
      `flap_threshold_high` tinyint(3) NOT NULL DEFAULT '30',
      `max_checks` tinyint(3) NOT NULL DEFAULT '1',
      `date_mod` timestamp NULL DEFAULT NULL,
      `date_creation` timestamp NULL DEFAULT NULL,
      PRIMARY KEY (`id`)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_servicetemplates");
   }
   if (!$DB->tableExists('glpi_plugin_siem_itils_scheduleddowntimes')) {
      $query = "CREATE TABLE `glpi_plugin_siem_itils_scheduleddowntimes` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `plugin_siem_scheduleddowntimes_id` int(11) NOT NULL,
      `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
      `items_id` int(11) NOT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `unicity` (`items_id`,`itemtype`,`plugin_siem_scheduleddowntimes_id`),
      KEY `item` (`itemtype`, `items_id`)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_itils_scheduleddowntimes");
   }
   if (!$DB->tableExists('glpi_plugin_siem_scheduleddowntimes')) {
      $query = "CREATE TABLE `glpi_plugin_siem_scheduleddowntimes` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `comment` text COLLATE utf8_unicode_ci DEFAULT NULL,
      `is_service` tinyint(1) NOT NULL DEFAULT 0,
      `items_id_target` int(11) NOT NULL,
      `is_fixed` tinyint(1) NOT NULL DEFAULT 1,
      `begin_date_planned` timestamp NOT NULL,
      `end_date_planned` timestamp NOT NULL,
      `begin_date_actual` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
      `end_date_actual` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
      `is_cancelled` tinyint(1) NOT NULL DEFAULT 0,
      `date_mod` timestamp NULL DEFAULT NULL,
      `date_creation` timestamp NULL DEFAULT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_scheduleddowntimes");
   }
   if (!$DB->tableExists('glpi_plugin_siem_acknowledgements')) {
      $query = "CREATE TABLE `glpi_plugin_siem_acknowledgements` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
      `items_id` int(11) NOT NULL,
      `status` tinyint(3) NOT NULL,
      `users_id` int(11) NOT NULL,
      `comment` text COLLATE utf8_unicode_ci DEFAULT NULL,
      `is_sticky` tinyint(1) NOT NULL DEFAULT 1 COMMENT 'If 1, no notifications are sent when going between problem states',
      `date_mod` timestamp NULL DEFAULT NULL,
      `date_creation` timestamp NULL DEFAULT NULL,
      `date_expiration` timestamp NULL DEFAULT NULL,
      PRIMARY KEY (`id`),
      KEY `item` (`items_id`,`itemtype`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
      $DB->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_acknowledgements");
   }

   $siemconfig = Config::getConfigurationValues('plugin:siem');
   if (!count($siemconfig)) {
      $DB->insert('glpi_configs', [
         'context' => 'plugin:siem',
         'name' => 'default_event_filter_action',
         'value' => '0'
      ]);
      $DB->insert('glpi_configs', [
         'context' => 'plugin:siem',
         'name' => 'request_type',
         'value' => '-1'
      ]);
   }
   CronTask::register('PluginSIEMEvent', 'pollevents', 60, ['state' => CronTask::STATE_WAITING]);
   return true;
}

function plugin_siem_uninstall()
{
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_events');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_itils_events');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_hosts');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_services');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_servicetemplates');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_itils_scheduleddowntimes');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_scheduleddowntimes');
   PluginSIEMDBUtil::dropTableOrDie('glpi_plugin_siem_acknowledgements');
   Config::deleteConfigurationValues('plugin:siem');
   CronTask::unregister('siem');
   return true;
}

function plugin_siemsensors_poll_sensor(array $params)
{
   if (!isset($params['sensor']) || !isset($params['service_ids'])) {
      return [];
   }
   switch ($params['sensor']) {
      case 'ping':
         return PluginSiemSensorPing::invokePoll($params['service_ids']);
      case 'http_ok':
         return PluginSiemSensorHttp_OK::invokePoll($params['service_ids']);
   }
}

function plugin_siem_getAddSearchOptions($itemtype)
{
   $opt = [];
   if (method_exists($itemtype, 'getAddSearchOptions')) {
      $opt = call_user_func([$itemtype, 'getAddSearchOptions']);
   }
   return $opt;
}