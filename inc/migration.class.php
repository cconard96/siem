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

use CronTask;
use DBmysql;
use Migration as GlpiMigration;
use ReflectionClass;

/**
 * Handles migrating between plugin versions
 */
class Migration
{
   private const BASE_VERSION = '1.0.0';

   /** @var GlpiMigration */
   protected $glpiMigration;

   /** @var DBmysql */
   protected $db;

   public function __construct(string $version)
   {
      global $DB;
      $this->glpiMigration = new GlpiMigration($version);
      $this->db = $DB;
   }

   public function applyMigrations()
   {
      $rc = new ReflectionClass($this);
      $otherMigrationFunctions = array_map(static function ($rm) use ($rc) {
         return $rm->getShortName();
      }, array_filter($rc->getMethods(), static function ($m) {
         return preg_match('/(?<=^apply_)(.*)(?=_migration$)/', $m->getShortName());
      }));

      if (count($otherMigrationFunctions)) {
         // Map versions to functions
         $versionMap = [];
         foreach ($otherMigrationFunctions as $function) {
            $ver = str_replace(['apply_', '_migration', '_'], ['', '', '.'], $function);
            $versionMap[$ver] = $function;
         }

         // Sort semantically
         uksort($versionMap, 'version_compare');

         // Get last known recorded version. If none exists, assume this is 1.0.0 (start migration from beginning).
         // Migrations should be replayable so nothing should be lost on multiple runs.
         $lastKnownVersion = \Config::getConfigurationValues('plugin:siem')['plugin_version'] ?? self::BASE_VERSION;
         // Remove alpha, beta, rc suffix (Handled by replaying the last version)
         $lastKnownVersion = explode('-', $lastKnownVersion, 2)[0];

         // Call each migration in order starting from the last known version
         foreach ($versionMap as $version => $func) {
            // Last known version is the same or greater than release version
            if (version_compare($lastKnownVersion, $version, '<=')) {
               $this->$func();
               $this->glpiMigration->executeMigration();
               if ($version !== self::BASE_VERSION) {
                  $this->setPluginVersionInDB($version);
                  $lastKnownVersion = $version;
               }
            }
         }
      }
   }

   private function setPluginVersionInDB($version)
   {
      $this->db->updateOrInsert(\Config::getTable(), [
         'value'     => $version,
         'context'   => 'plugin:siem',
         'name'      => 'plugin_version'
      ], [
         'context'   => 'plugin:siem',
         'name'      => 'plugin_version'
      ]);
   }

   /**
    * Apply the migrations for the base plugin version (1.0.0).
    */
   private function apply_1_0_0_migration()
   {
      if (!$this->db->tableExists('glpi_plugin_siem_events')) {
         $query = "CREATE TABLE `glpi_plugin_siem_events` (
            `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
            `name` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
            `date` datetime DEFAULT NULL,
            `content` longtext COLLATE utf8_unicode_ci,
            `date_creation` datetime DEFAULT NULL,
            `significance` tinyint(4) NOT NULL,
            `correlation_id` VARCHAR(23) DEFAULT NULL,
            `date_mod` datetime DEFAULT NULL,
            `plugin_siem_services_id` int(11) NOT NULL,
            PRIMARY KEY (`id`),
            KEY `name` (`name`),
            KEY `date` (`date`),
            KEY `date_creation` (`date_creation`),
            KEY `significance` (`significance`),
            KEY `correlation_id` (`correlation_id`),
            KEY `plugin_siem_services_id` (`plugin_siem_services_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_events");
      }
      if (!$this->db->tableExists('glpi_plugin_siem_itils_events')) {
         $query = "CREATE TABLE `glpi_plugin_siem_itils_events` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
            `items_id` int(11) NOT NULL DEFAULT '0',
            `plugin_siem_events_id` int(11) unsigned NOT NULL DEFAULT '0',
            PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_itils_events");
      }
      if (!$this->db->tableExists('glpi_plugin_siem_hosts')) {
         $query = "CREATE TABLE `glpi_plugin_siem_hosts` (
         `id` int(11) NOT NULL AUTO_INCREMENT,
         `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
         `items_id` int(11) NOT NULL,
         `plugin_siem_services_id_availability` int(11) DEFAULT NULL,
         `is_reachable` tinyint(1) NOT NULL DEFAULT '1',
         `date_mod` timestamp NULL DEFAULT NULL,
         `date_creation` timestamp NULL DEFAULT NULL,
         PRIMARY KEY (`id`),
         KEY `item` (`items_id`,`itemtype`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_hosts");
      }
      if (!$this->db->tableExists('glpi_plugin_siem_services')) {
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
         `sensor_params` text COLLATE utf8_unicode_ci DEFAULT NULL,
         PRIMARY KEY (`id`),
         KEY `plugin_siem_servicetemplates_id` (`plugin_siem_servicetemplates_id`),
         KEY `plugin_siem_hosts_id` (`plugin_siem_hosts_id`),
         KEY `is_flapping` (`is_flapping`),
         KEY `is_acknowledged` (`is_acknowledged`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_services");
      }
      if (!$this->db->fieldExists('glpi_plugin_siem_services', 'sensor_params')) {
         $this->glpiMigration->addField('glpi_plugin_siem_services', 'sensor_params', 'text');
      }

      if (!$this->db->tableExists('glpi_plugin_siem_servicetemplates')) {
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
         `plugins_id` int(11) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Indicates which plugin (or the core) logged this event. Used to delegate translations and other functions',
         `sensor` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
         `is_stateless` tinyint(1) NOT NULL DEFAULT '0',
         `flap_threshold_low` tinyint(3) NOT NULL DEFAULT '15',
         `flap_threshold_high` tinyint(3) NOT NULL DEFAULT '30',
         `max_checks` tinyint(3) NOT NULL DEFAULT '1',
         `date_mod` timestamp NULL DEFAULT NULL,
         `date_creation` timestamp NULL DEFAULT NULL,
         `sensor_params` text COLLATE utf8_unicode_ci DEFAULT NULL,
         PRIMARY KEY (`id`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_servicetemplates");
      }

      if (!$this->db->fieldExists('glpi_plugin_siem_servicetemplates', 'sensor_params')) {
         $this->glpiMigration->addField('glpi_plugin_siem_servicetemplates', 'sensor_params', 'text');
      }

      if (!$this->db->tableExists('glpi_plugin_siem_itils_scheduleddowntimes')) {
         $query = "CREATE TABLE `glpi_plugin_siem_itils_scheduleddowntimes` (
         `id` int(11) NOT NULL AUTO_INCREMENT,
         `plugin_siem_scheduleddowntimes_id` int(11) NOT NULL,
         `itemtype` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
         `items_id` int(11) NOT NULL,
         PRIMARY KEY (`id`),
         UNIQUE KEY `unicity` (`items_id`,`itemtype`,`plugin_siem_scheduleddowntimes_id`),
         KEY `item` (`itemtype`, `items_id`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_itils_scheduleddowntimes");
      }
      if (!$this->db->tableExists('glpi_plugin_siem_scheduleddowntimes')) {
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
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_scheduleddowntimes");
      }
      if (!$this->db->tableExists('glpi_plugin_siem_acknowledgements')) {
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
         $this->db->queryOrDie($query, "1.0.0 add table glpi_plugin_siem_acknowledgements");
      }

      $this->glpiMigration->addConfig([
         'default_event_filter_action' => 0,
         'request_type'                => -1
      ], 'plugin:siem');

      CronTask::register(Event::class, 'pollevents', 60, ['state' => CronTask::STATE_WAITING]);
   }
}
