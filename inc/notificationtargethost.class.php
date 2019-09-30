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
 * PluginSIEMNotificationTargetHost Class
 * @since 1.0.0
 **/
class PluginSIEMNotificationTargetHost extends NotificationTarget
{


   function getEvents()
   {
      return [
         'recovery_soft' => __('Soft recovery'),
         'recovery_hard' => __('Hard recovery'),
         'problem_soft' => __('Soft problem'),
         'problem_hard' => __('Hard problem'),
         'flapping_start' => __('Flapping started'),
         'flapping_stop' => __('Flapping stopped'),
         'flapping_disable' => __('Flapping disabled')
      ];
   }


   function addDataForTemplate($event, $options = [])
   {

      $events = $this->getAllEvents();
      $host = new PluginSiemHost();
      $host->getFromDB($options['id']);
      $service = $host->getAvailabilityService();

      $this->data['##plugin_siem_host.action##'] = $events[$event];
      $this->data['##plugin_siem_host.name##'] = $host->getHostName();
      // TODO Finish

      $this->getTags();
      foreach ($this->tag_descriptions[NotificationTarget::TAG_LANGUAGE] as $tag => $values) {
         if (!isset($this->data[$tag])) {
            $this->data[$tag] = $values['label'];
         }
      }
   }


   function getTags()
   {

      $tags = [
         'plugin_siem_host.name' => __('Name'),
         'plugin_siem_host.itemtype' => __('Item type'),
         'plugin_siem_host.availabilityservice' => __('Availability service'),
         'plugin_siem_host.status' => __('Status'),
         'plugin_siem_host.is_flapping' => __('Is flapping'),
         'plugin_siem_host.state_type' => __('State type'),
         'plugin_siem_host.current_check' => __('Current checkk'),
         'plugin_siem_host.max_check' => __('Max checks'),
         'plugin_siem_host.flap_detection' => __('Flap detection'),
         'plugin_siem_host.check_interval' => __('Check interval'),
         'plugin_siem_host.check_mode' => __('Check mode'),
         'plugin_siem_host.logger' => __('Logger'),
         'plugin_siem_host.sensor' => __('Sensor'),
      ];

      foreach ($tags as $tag => $label) {
         $this->addTagToList(['tag' => $tag,
            'label' => $label,
            'value' => true]);
      }

      asort($this->tag_descriptions);
   }

}