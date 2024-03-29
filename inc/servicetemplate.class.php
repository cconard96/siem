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

use CommonDBTM;
use CommonITILObject;
use Dropdown;
use Html;
use Plugin;

/**
 * SIEMServiceTemplate class.
 *
 * @since 1.0.0
 */
class ServiceTemplate extends CommonDBTM
{
   public static $rightname = 'plugin_siem_servicetemplate';


   public static function getTypeName($nb = 0)
   {
      return _n('Service template', 'Service templates', $nb);
   }

   public static function getIcon()
   {
      return 'fas fa-layer-group';
   }

   public static function getMenuContent()
   {
      $menu = parent::getMenuContent();
      $menu['links']['search'] = self::getSearchURL(false);
      if (self::canCreate()) {
         $menu['links']['add'] = self::getFormURL(false);
      }
      return $menu;
   }

   public static function getAdditionalMenuLinks()
   {
      $links = [];
      $links['add'] = self::getFormURL(false);
      if (count($links)) {
         return $links;
      }
      return false;
   }

   protected function getFormFields()
   {
      $fields = [
            'name' => [
               'label' => __('Name'),
               'type' => 'text'
            ],
            'comment' => [
               'label' => __('Comment'),
               'type' => 'textarea'
            ],
            'priority' => [
               'label' => __('Priority'),
               'type' => 'select',
               'values' => [
                  0 => CommonITILObject::getPriorityName(0),
                  -5 => CommonITILObject::getPriorityName(-5),
                  -4 => CommonITILObject::getPriorityName(-4),
                  -3 => CommonITILObject::getPriorityName(-3),
                  -2 => CommonITILObject::getPriorityName(-2),
                  -1 => CommonITILObject::getPriorityName(-1)
               ],
               //FIXME What is the purpose of requiring the following 2 keys?
               'itemtype_name' => null,
               'itemtype' => null
            ],
            'calendars_id' => [
               'label' => __('Notification period'),
               'type' => 'Calendar',
            ],
            'notificationinterval' => [
               'label' => __('Notification interval'),
               'type' => 'number',
            ],
            'check_interval' => [
               'label' => __('Check interval'),
               'type' => 'number',
            ],
            'use_flap_detection' => [
               'label' => __('Enable flapping detection'),
               'type' => 'yesno',
            ],
            'check_mode' => [
               'label' => __('Enable flapping detection'),
               'type' => 'select',
               'values' => [
                  Service::CHECK_MODE_ACTIVE => __('Active'),
                  Service::CHECK_MODE_PASSIVE => __('Passive'),
                  Service::CHECK_MODE_HYBRID => __('Hybrid'),
               ],
               'itemtype_name' => null,
               'itemtype' => null
            ],
            'is_stateless' => [
               'label' => __('Stateless'),
               'type' => 'yesno',
            ],
            'flap_threshold_low' => [
               'label' => __('Flapping lower threshold'),
               'name' => 'flap_threshold_low',
               'type' => 'number',
            ],
            'flap_threshold_high' => [
               'label' => __('Flapping upper threshold'),
               'name' => 'flap_threshold_high',
               'type' => 'number',
            ],
            'max_checks' => [
               'label' => __('Max checks'),
               'name' => 'max_checks',
               'type' => 'number',
            ],
            'plugins_id' => [
               //FIXME Why doesn't type 'Plugin' work here?
               'label' => __('Plugin'),
               'type' => 'select',
               'values' => [],
               'itemtype_name' => null,
               'itemtype' => null
            ],
            'sensor' => [
               'label' => __('Sensor'),
               'type' => 'select',
               'values' => [],
               'itemtype_name' => null,
               'itemtype' => null
            ]
         ] + parent::getFormFields();
      return $fields;
   }

   function showForm($ID, $options = []) {

      $this->initForm($ID, $options);
      $this->showFormHeader($options);

      echo "<tr class='tab_bg_1'>";
      echo '<td>' .sprintf(__('%1$s%2$s'), __('Name'),
            (isset($options['withtemplate'])
            && $options['withtemplate'] ? '*' : '')).
         '</td>';
      echo '<td>';
      $objectName = autoName($this->fields['name'], 'name', false, self::getType(), $this->fields['entities_id'] ?? -1);
      Html::autocompletionTextField($this, 'name', ['value' => $objectName]);
      echo '</td>';
      echo '<td>' .__('Comments'). '</td>';
      echo "<td rowspan='2' class='middle'>";
      echo "<textarea cols='45' rows='4' name='comment' >".
         $this->fields["comment"];
      echo '</textarea></td></tr>';

      $rand = mt_rand();
      echo '<tr><td>' .__('Plugin', 'siem'). '</td>';
      echo '<td>';
      Plugin::dropdown([
         'name'      => 'plugins_id',
         'rand'      => $rand,
         'on_change' => "window.pluginSiem.updateSensorDropdown('#dropdown_plugins_id$rand', '#dropdown_sensor$rand')",
         'value'  => $this->fields['plugins_id'] ?? 0
      ]);
      echo '</td></tr>';

      echo '<tr><td>' .__('Sensor', 'siem'). '</td>';
      echo '<td>';
      Dropdown::showFromArray('sensor', [], [
         'rand'      => $rand,
         'disabled'  => true,
         'value'     => $this->fields['sensor'] ?? 0,
         'on_change' => "window.pluginSiem.updateServiceParamsFields(\"#dropdown_plugins_id$rand\", \"#dropdown_sensor$rand\")",
      ]);
      echo Html::scriptBlock("$(document).ready(function() {\$('#dropdown_plugins_id$rand').trigger('change')});");
      echo '</td>';
      echo '<td>' .__('Priority', 'siem'). '</td>';
      echo '<td>';
      Dropdown::showFromArray('priority', [
         1 => _x('priority', 'Very low'),
         2 => _x('priority', 'Low'),
         3 => _x('priority', 'Medium'),
         4 => _x('priority', 'High'),
         5 => _x('priority', 'Very high'),
         6 => _x('priority', 'Major'),
      ], [
         'rand'   => $rand,
         'value'  => $this->fields['priority'] ?? 3
      ]);
      Html::showToolTip(__('The criticality of the service', 'siem'));
      echo '</td></tr>';

      echo '<tr><td>' .__('Max checks', 'siem'). '</td>';
      echo '<td>';
      echo Html::input('max_checks', [
         'type' => 'number',
         'min'    => 1,
         'max'    => 100,
         'value'  => isset($this->fields['max_checks']) && !empty($this->fields['max_checks']) ?
            $this->fields['max_checks'] : 1
      ]);
      Html::showToolTip(__('The number of checks on the service needed before it can change from being in a soft state to a hard state.', 'siem'));
      echo '</td>';
      echo '<td>' .__('Check interval', 'siem'). '</td>';
      echo '<td>';
      echo Html::input('check_interval', [
         'type' => 'number',
         'min'    => 1,
         'max'    => MONTH_TIMESTAMP,
         'value'  => isset($this->fields['check_interval']) && !empty($this->fields['check_interval']) ?
            $this->fields['check_interval'] : 1
      ]);
      Html::showToolTip(__('How often the sensor will be polled for the service in minutes (Ignored for passive sensors).', 'siem'));
      echo '</td></tr>';

      echo "<tr><th colspan='4'>".__('Flapping detection settings', 'siem'). '</th></tr>';
      echo '<tr><td>' .__('Use flapping detection', 'siem'). '</td>';
      echo '<td>';
      Dropdown::showYesNo('use_flap_detection', '1', -1, [
         'rand'   => $rand
      ]);
      echo '</td>';
      echo '<td>' .__('Lower flapping threshold', 'siem'). '</td>';
      echo '<td>';
      echo Html::input('flap_threshold_low', [
         'type' => 'number',
         'min'    => 1,
         'max'    => 100,
         'value'  => isset($this->fields['flap_threshold_low']) && !empty($this->fields['flap_threshold_low']) ?
            $this->fields['flap_threshold_low'] : 15
      ]);
      Html::showToolTip(__('The maximum amount of change between states needed before the service is no longer considered flapping.
         This is calculated over a sample size of 20 checks', 'siem'));
      echo '</td></tr>';

      echo '<tr><td>' .__('Higher flapping threshold', 'siem'). '</td><td>';
      echo Html::input('flap_threshold_high', [
         'type' => 'number',
         'min'    => 1,
         'max'    => 100,
         'value'  => isset($this->fields['flap_threshold_high']) && !empty($this->fields['flap_threshold_high']) ?
            $this->fields['flap_threshold_high'] : 30
      ]);
      Html::showToolTip(__('The minimum amount of change between states needed before the service is considered flapping.
         This is calculated over a sample size of 20 checks', 'siem'));
      echo '</td></tr>';

      echo "<tr><th colspan='4'>".__('Alert settings', 'siem'). '</th></tr>';
      echo '<tr><td>' .__('Notification interval', 'siem'). '</td><td>';
      echo Html::input('notificationinterval', [
         'type' => 'number',
         'min'    => 0,
         'max'    => MONTH_TIMESTAMP,
         'value'  => isset($this->fields['notificationinterval']) && !empty($this->fields['notificationinterval']) ?
            $this->fields['notificationinterval'] : 0
      ]);
      Html::showToolTip(__('The amount of time between alerts for this service when not in downtime or acknowledged (0 for one-time alerts).', 'siem'));
      echo '</td></tr>';

      echo "<tr><th colspan='4'>".__('Service Parameters', 'siem'). '</th></tr>';
      echo "<tr><td colspan='4' id='service-params'>".__('No parameters supported for this sensor')."</td></tr>";

      $this->showFormButtons($options);

      return true;
   }

   /**
    * Show a list of all hosts with services using this template
    */
   public function showHosts()
   {

   }

   /**
    * Show a list of all services using this template
    */
   public function showServices()
   {
      $siemservice = new Service();
      $siemhost = new Host();
      $services = $siemservice->find(['plugin_siem_servicetemplates_id' => $this->getID()]);

      echo '<table><tr>';
      echo '<th>' .__('Host'). '</th>';
      echo '<th>' .__('Last check'). '</th>';
      echo '<th>' .__('Status'). '</th>';
      echo '<th>' .__('Is hard'). '</th>';
      echo '<th>' .__('Is flapping'). '</th>';
      echo '<th>' .__('Is acknowledged'). '</th>';
      echo '<th>' .__('Is active'). '</th>';
      echo '</tr>';
      if (!count($services)) {
         echo "<tr><td colspan='7'>".__('No services'). '</td></tr>';
      } else {
         foreach ($services as $service) {
            $host = $siemhost->find(['id' => 'plugin_siem_hosts_id']);
            $host = reset($host);
            $assetinfo = $host->getItemInfo();
            echo '<tr>';
            echo '<td>'.Html::link($assetinfo['name'], $host['itemtype']::getFormURLWithID($host['items_id'])). '</td>';
            echo '<td>'.Toolbox::getHumanReadableTimeDiff($service['last_check']). '</td>';
            echo '<td>'.Service::getStatusName($service['status']). '</td>';
            echo '<td>' . ($service['is_hard'] ? __('True') : __('False')) . '</td>';
            echo '<td>' . ($service['is_flapping'] ? __('True') : __('False')) . '</td>';
            echo '<td>' . ($service['is_acknowledged'] ? __('True') : __('False')) . '</td>';
            echo '<td>' . ($service['is_active'] ? __('True') : __('False')) . '</td>';
            echo '</tr>';
         }
      }
   }
}