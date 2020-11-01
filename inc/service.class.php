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


/**
 * PluginSIEMService class.
 * This represents a software, service, or metric on a host device that is able to be monitored.
 *
 * @since 1.0.0
 */
class PluginSiemService extends CommonDBTM
{
   use PluginSiemMonitored;

   public static $rightname = 'plugin_siem_service';

   /** Service is functioning as expected. */
   const STATUS_OK = 0;

   /** Service is functional but functionality or performance is limited.
    * Valid for stateful services only.*/
   const STATUS_WARNING = 1;

   /** Service is not functioning properly.
    * Valid for stateful services only. */
   const STATUS_CRITICAL = 2;

   /** Service is not being monitored */
   const STATUS_UNKNOWN = 3;

   /** This service is actively polled. */
   const CHECK_MODE_ACTIVE = 0;

   /** This service sends events to GLPI as needed. */
   const CHECK_MODE_PASSIVE = 1;

   /** This service can operate in both active and passive modes. */
   const CHECK_MODE_HYBRID = 2;

   protected $twig_compat = true;


   public static function getTypeName($nb = 0)
   {
      return _n('Service', 'Services', $nb, 'siem');
   }

   public function post_getFromDB()
   {
      // Merge fields with the template
      $template = new PluginSiemServiceTemplate();
      $template->getFromDB($this->fields['plugin_siem_servicetemplates_id']);
      foreach ($template->fields as $field => $value) {
         if ($field !== 'id') {
            $this->fields[$field] = $value;
         }
      }
   }

   public function isHostless()
   {
      return $this->fields['plugin_siem_hosts_id'] < 0;
   }

   public static function getStatusName($status)
   {
      switch ($status) {
         case self::STATUS_OK:
            return __('OK');
         case self::STATUS_CRITICAL:
            return __('Critical');
         case self::STATUS_WARNING:
            return __('Warning');
         case self::STATUS_UNKNOWN:
         default:
            return __('Unknown');
      }
   }

   public static function getCheckModeName($check_mode)
   {
      switch ($check_mode) {
         case self::CHECK_MODE_ACTIVE:
            return __('Active');
         case self::CHECK_MODE_PASSIVE:
            return __('Passive');
         case self::CHECK_MODE_HYBRID:
            return __('Hybrid');
         default:
            return __('Unknown');
      }
   }

   public static function getBackgroundColorClass(int $status): string
   {
      switch ($status) {
         case self::STATUS_CRITICAL:
            return 'bg-danger';
         case self::STATUS_OK:
            return 'bg-success';
         case self::STATUS_WARNING:
         case self::STATUS_UNKNOWN:
            return 'bg-warning';
      }
      return '';
   }

   public function getServiceInfoDisplay()
   {
      $status = self::getStatusName($this->fields['status']);
      $status_since_diff = PluginSIEMToolbox::getHumanReadableTimeDiff($this->fields['status_since']);
      $last_check_diff = PluginSIEMToolbox::getHumanReadableTimeDiff($this->fields['last_check']);
      $service_stats = [
         PluginSiemHost::getTypeName(1) => $this->getHostName(),
         __('Last status change') => ($status_since_diff === null ? __('No change') : $status_since_diff),
         __('Last check') => ($last_check_diff === null ? __('Not checked') : $last_check_diff),
         __('Flapping') => $this->isFlapping() ? __('Yes') : __('No')
      ];
      $toolbar_buttons = [
         [
            'label' => __('Check now'),
            'action' => 'hostCheckNow()',
            'type' => 'button',
         ],
         [
            'label' => __('Schedule downtime'),
            'action' => 'hostScheduleDowtime()',
            'type' => 'button',
         ]
      ];
      $btn_classes = 'btn btn-primary mx-1';
      $toolbar = "<div id='service-actions-toolbar'><div class='btn-toolbar'>";
      foreach ($toolbar_buttons as $button) {
         if ($button['type'] === 'button') {
            $toolbar .= "<button type='button' class='{$btn_classes}' onclick='{$button['action']}'>{$button['label']}</button>";
         } else if ($button['type'] === 'link') {
            $toolbar .= "<a href='{$button['action']}' class='{$btn_classes}'>{$button['label']}</a>";
         }
      }
      $toolbar .= '</div></div>';
      $out = $toolbar;
      $out .= "<div id='service-info' class='inline'>";
      $out .= "<table class='text-center w-100'><thead><tr>";
      $out .= "<th colspan='2'><h3>{$status}</h3></th>";
      $out .= '</tr></thead><tbody>';
      foreach ($service_stats as $label => $value) {
         $out .= "<tr><td><p style='font-size: 1.5em; margin: 0'>{$label}</p><p style='font-size: 1.25em; margin: 0'>{$value}</p></td></tr>";
      }
      $out .= '</tbody></table></div>';
      return $out;
   }

   private function dispatchSIEMServiceEvent($eventName, $is_hard_status = true)
   {
      global $CONTAINER;
      if (!isset($CONTAINER) || !$CONTAINER->has(EventDispatcher::class)) {
         return;
      }
      $dispatcher = $CONTAINER->get(EventDispatcher::class);
      $dispatcher->dispatch($eventName, new SIEMServiceEvent($this, $is_hard_status));
   }

   public function checkFlappingState()
   {
      //FIXME Does not seem to work right. Allow soft/hard states.
      global $DB;
      if (!$this->fields['use_flap_detection'] || $this->isScheduledDown()) {
         // Ignore flapping status if check is disabled or if the service is expected to be down.
         return;
      }
      // Get caches array of last 20 state changes
      $flap_cache = $this->getFlappingStateCache();
      $total_state_change = 0;
      // Number of states that get cached
      $flap_check_max = 20;
      $weight = 0.80;
      $state_changes = 0.00;
      $last_state = $flap_cache[0];

      foreach ($flap_cache as $iValue) {
         if ($iValue !== $last_state) {
            $state_changes += $weight;
         }
         // Newer state changes are weighted heigher
         $weight += 0.02;
         $last_state = $iValue;
      }
      $total_state_change = (int)(($state_changes / 20.00) * 100.00);
      if ($total_state_change < $this->fields['flap_threshold_low']) {
         // End flapping
         $this->update([
            'id' => $this->getID(),
            'is_flapping' => 0
         ]);
      } else if ($total_state_change > $this->fields['flap_threshold_high']) {
         // Begin flapping
         $this->update([
            'id' => $this->getID(),
            'is_flapping' => 1
         ]);
      }
   }

   /**
    * Called every time an PluginSIEMEvent is added so that the related service state can be updated.
    *
    * @param PluginSiemEvent $event The event that was added
    * @return bool True if the service was updated successfully
    * @since 1.0.0
    */
   public static function onEventAdd(PluginSiemEvent $event)
   {
      $service = new self();
      if ($event->fields['plugin_siem_services_id'] >= 0 &&
         $service->getFromDB($event->fields['plugin_siem_services_id'])) {
         $last_status = $service->fields['status'];
         $was_flapping = $service->isFlapping();
         $significance = $event->fields['significance'];
         // Check downtime
         $in_downtime = $service->isScheduledDown();
         if (!$service->fields['is_stateless']) {
            $to_update = [
               'id' => $service->getID(),
               'last_check' => $_SESSION['glpi_currenttime']
            ];
            // Stateful service checks
            if ($significance === PluginSiemEvent::EXCEPTION && $last_status === self::STATUS_OK) {
               if (!$in_downtime) {
                  // Transition to problem state
                  $to_update['_problem'] = true;
                  if ($service->isHardStatus()) {
                     $to_update['is_hard_status'] = false;
                  }
               }
            } else if ($significance === PluginSiemEvent::EXCEPTION && $last_status !== self::STATUS_OK) {
               if (!$in_downtime) {
                  if (!$service->isHardStatus()) {
                     $to_update['current_check'] = $service->fields['current_check'] + 1;
                     if ($service->fields['current_check'] + 1 >= $service->fields['max_checks']) {
                        $to_update['is_hard_status'] = true;
                     }
                  }
               }
            } else if ($significance === PluginSiemEvent::INFORMATION && $last_status !== self::STATUS_OK) {
               // Transition to recovery state
               $to_update['_recovery'] = true;
               // Recoveries should cancel all non-fixed, active downtimes
               if ($in_downtime) {
                  $downtime = new PluginSiemScheduledDowntime();
                  $downtimes = PluginSiemScheduledDowntime::getForHostOrService($service->getID());
                  while ($data = $downtimes->next()) {
                     if ($data['is_fixed'] === 0) {
                        $downtime->update([
                           'id' => $data['id'],
                           '_cancel' => true
                        ]);
                     }
                  }
               }
            }
            // Get current flapping status cache, fixing it if needed.
            $flap_cache = $service->getFlappingStateCache();
            // Remove oldest status
            array_shift($flap_cache);
            // Append new status
            $flap_cache[] = $event->fields['significance'];
            // Save cache and then update the service in DB
            $to_update['flap_state_cache'] = json_encode($flap_cache);
            $service->update($to_update);
            // Check flapping state if not in downtime and if it is enabled
            $service->checkFlappingState();
            // Update status change timestamp if needed
            if ($service->isFlapping() !== $was_flapping || $last_status !== $service->fields['status']) {
               $service->update([
                  'id' => $service->getID(),
                  'status_since' => $_SESSION['glpi_currenttime']
               ]);
            }
         } else {
            // Stateless service checks
         }
      }
      return true;
   }

   private function resetFlappingStateCache()
   {
      $flap_cache = array_fill(0, 20, (string)self::STATUS_OK);
      $this->update([
         'id' => $this->getID(),
         'flap_state_cache' => json_encode($flap_cache)
      ]);
   }

   private function getFlappingStateCache()
   {
      $flap_cache = json_decode($this->fields['flap_state_cache'], true);
      if (!$flap_cache || !count($flap_cache)) {
         $this->resetFlappingStateCache();
      } else if (count($flap_cache) < 20) {
         $flap_cache = array_merge(array_fill(0, 20 - count($flap_cache), self::STATUS_OK), $flap_cache);
         $this->update([
            'id' => $this->getID(),
            'flap_state_cache' => json_encode($flap_cache)
         ]);
      } else if (count($flap_cache) > 20) {
         $flap_cache = array_slice($flap_cache, -20);
         $this->update([
            'id' => $this->getID(),
            'flap_state_cache' => json_encode($flap_cache)
         ]);
      }
      return json_decode($this->fields['flap_state_cache'], true);
   }

   public function prepareInputForUpdate($input)
   {
      if (isset($input['_problem'])) {
         if (isset($input['is_hard_status']) && !$input['is_hard_status']) {
            $input['status'] = self::STATUS_WARNING;
         } else {
            $input['status'] = self::STATUS_CRITICAL;
         }
      } else if (isset($input['_recovery'])) {
         $input['status'] = self::STATUS_OK;
         if (isset($input['is_hard_status']) && $input['is_hard_status']) {
            $input['current_check'] = 0;
         }
      }
      return $input;
   }

   public function post_updateItem($history = 1)
   {
      $host = new PluginSiemHost();
      $is_hostservice = false;
      if ($host = $this->getHost()) {
         if ($host->fields['plugin_siem_services_id_availability'] === $this->getID()) {
            $is_hostservice = true;
         }
      }
//      if (isset($this->input['_problem'])) {
//         if ($is_hostservice) {
//            $host->dispatchSIEMHostEvent(SIEMHostEvent::HOST_DOWN, $this->isHardStatus());
//         } else {
//            $this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_PROBLEM, $this->isHardStatus());
//         }
//      } else if (isset($this->input['_recovery'])) {
//         if ($is_hostservice) {
//            $host->dispatchSIEMHostEvent(SIEMHostEvent::HOST_UP, $this->isHardStatus());
//         } else {
//            $this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_RECOVERY, $this->isHardStatus());
//         }
//      }
      if (isset($this->input['is_active']) && $this->input['is_active'] !== $this->fields['is_active']) {
         if ($this->input['is_active']) {
            //$this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_ENABLE);
         } else {
            //$this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_DISABLE);
            if ($is_hostservice) {
               $host->update([
                  'id' => $host->getID(),
                  'status' => self::STATUS_UNKNOWN
               ]);
            }
         }
      }
      if (isset($this->input['_acknowledge'])) {
         if ($is_hostservice) {
            //$host->dispatchSIEMHostEvent(SIEMHostEvent::HOST_ACKNOWLEDGE);
         } else {
            //$this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_ACKNOWLEDGE);
         }
      }
      if (isset($this->input['use_flap_detection']) &&
         $this->input['use_flap_detection'] !== $this->fields['use_flap_detection']) {
         if (!$this->input['use_flap_detection']) {
            if ($is_hostservice) {
               //$host->dispatchSIEMHostEvent(SIEMHostEvent::HOST_DISABLE_FLAPPING);
            } else {
               //$this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_DISABLE_FLAPPING);
            }
         }
      } else if (isset($this->input['is_flapping']) && $this->input['is_flapping'] !== $this->fields['is_flapping']) {
         if ($this->input['is_flapping']) {
            if ($is_hostservice) {
               //$host->dispatchSIEMHostEvent(SIEMHostEvent::HOST_START_FLAPPING);
            } else {
               //$this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_START_FLAPPING);
            }
         } else {
            if ($is_hostservice) {
               //$host->dispatchSIEMHostEvent(SIEMHostEvent::HOST_STOP_FLAPPING);
            } else {
               //$this->dispatchSIEMServiceEvent(SIEMServiceEvent::SERVICE_STOP_FLAPPING);
            }
         }
      }
   }

   public static function getFormForHost(PluginSiemHost $host)
   {
      global $DB;
      $services = $host->getServices();
      foreach ($services as $service_id => &$service) {
         $status = self::getStatusName($service['status']);
         $service['badges'] = [];
         switch ($service['status']) {
            case self::STATUS_OK:
               $service['badges'][] = ['class' => 'badge badge-success', 'label' => $status];
               break;
            case self::STATUS_CRITICAL:
               $service['badges'][] = ['class' => 'badge badge-danger', 'label' => $status];
               break;
            case self::STATUS_WARNING:
               $service['badges'][] = ['class' => 'badge badge-warning', 'label' => $status];
               break;
         }
         if ($service['is_flapping']) {
            $service['badges'][] = ['class' => 'badge badge-warning', 'label' => __('Flapping')];
         }
         $service['status_since_diff'] = PluginSiemToolbox::getHumanReadableTimeDiff($service['status_since']);
         $eventiterator = $DB->request([
            'SELECT' => ['name'],
            'FROM' => PluginSiemEvent::getTable(),
            'WHERE' => [
               'plugin_siem_services_id' => $service_id
            ],
            'ORDERBY' => ['date DESC'],
            'LIMIT' => 1
         ]);
         $eventdata = $eventiterator->count() ? $eventiterator->next() : null;
         $service['link'] = self::getFormURLWithID($service_id);
         if ($eventdata !== null) {
            $service['latest_event_name'] = PluginSiemEvent::getLocalizedEventName($eventdata['name'], $service['plugins_id']);
         } else {
            $service['latest_event_name'] = null;
         }
      }
      return PluginSiemToolbox::getTwig()->render('elements/host_service_list.html.twig', [
         'services'  => $services
      ]);
   }

   protected function getFormFields()
   {
      $fields = [
            'plugin_siem_hosts_id' => [
               'label' => PluginSiemHost::getTypeName(1),
               'type' => 'PluginSiemHost'
            ],
            'plugin_siem_servicetemplates_id' => [
               'label' => PluginSiemServiceTemplate::getTypeName(1),
               'type' => 'PluginSiemServiceTemplate'
            ],
            'last_check' => [
               'label' => __('Last check'),
               'name' => 'last_check',
               'type' => 'date'
            ],
            'suppress_informational' => [
               'label' => __('Suppress informational'),
               'type' => 'yesno'
            ]
         ] + parent::getFormFields();
      return $fields;
   }

   protected function getFormFieldsToDrop($add = false)
   {
      $fields = [];
      if ($add === true) {
         $fields[] = 'id';
         //FIXME Why isn't this field dropped on add form?
         $fields[] = 'last_check';
         $fields[] = 'status';
         $fields[] = 'status_since';
         $fields[] = 'is_flapping';
         $fields[] = 'is_active';
         $fields[] = 'flap_state_cache';
         $fields[] = 'is_hard_status';
         $fields[] = 'current_check';
      }
      return $fields;
   }

   function rawSearchOptions()
   {
      $tab = [];
      $tab[] = [
         'id' => 'common',
         'name' => __('Characteristics')
      ];
//      $tab[] = [
//         'id'              => '2',
//         'table'           => $this->getTable(),
//         'field'           => '_name',
//         'name'            => __('Host'),
//         'massiveaction'   => false,
//         'datatype'        => 'specific'
//      ];
      $tab[] = [
         'id' => '3',
         'table' => PluginSiemServiceTemplate::getTable(),
         'field' => 'name',
         'linkfield' => 'plugin_siem_servicetemplates_id',
         'name' => __('Service template'),
         'datatype' => 'itemlink'
      ];
      $tab[] = [
         'id' => '4',
         'table' => self::getTable(),
         'field' => 'items_id',
         'name' => __('Item ID'),
         'datatype' => 'number'
      ];
      $tab[] = [
         'id' => '5',
         'table' => self::getTable(),
         'field' => 'status',
         'name' => __('Status'),
         'datatype' => 'specific'
      ];
      $tab[] = [
         'id' => '6',
         'table' => self::getTable(),
         'field' => 'is_flapping',
         'name' => __('Is flapping'),
         'datatype' => 'bool'
      ];
      $tab[] = [
         'id' => '7',
         'table' => self::getTable(),
         'field' => 'is_hard_status',
         'name' => __('Is hard status'),
         'datatype' => 'bool'
      ];
      $tab[] = [
         'id' => '19',
         'table' => self::getTable(),
         'field' => 'date_mod',
         'name' => __('Last update'),
         'datatype' => 'datetime',
         'massiveaction' => false
      ];
      $tab[] = [
         'id' => '121',
         'table' => self::getTable(),
         'field' => 'date_creation',
         'name' => __('Creation date'),
         'datatype' => 'datetime',
         'massiveaction' => false
      ];
      //TODO Add availability service search options
      return $tab;
   }

   public static function getSpecificValueToDisplay($field, $values, array $options = [])
   {

      global $DB;

      if (!is_array($values)) {
         $values = [$field => $values];
      }
      switch ($field) {
         case 'host_name' :
            /** @var CommonDBTM $itemtype */
            $itemtype = $values['itemtype'];
            $item_table = $itemtype::getTable();
            $iterator = $DB->request([
               'SELECT' => [$item_table.'.id', $item_table.'name'],
               'FROM'   => $item_table,
               'WHERE'  => ['id' => $values['items_id']]
            ]);
            if ($iterator->count()) {
               $item = $iterator->next();
               return Html::link($item['name'], $itemtype::getFormURLWithID($item['id']));
            }
            break;
         case 'status':
            return self::getStatusName($values[$field]);
      }
      return parent::getSpecificValueToDisplay($field, $values, $options);
   }

   public static function getDropdownForHost($hosts_id) {
      global $DB;

      $values = [];
      $service_table = self::getTable();
      $template_table = PluginSiemServiceTemplate::getTable();
      $iterator = $DB->request([
         'SELECT'    => [
            'glpi_plugin_siem_services.id',
            'name'
         ],
         'FROM'      => $service_table,
         'LEFT JOIN' => [
            $template_table => [
               'FKEY'   => [
                  $template_table   => 'id',
                  $service_table    => 'plugin_siem_servicetemplates_id'
               ]
            ]
         ],
         'WHERE'     => [
            'plugin_siem_hosts_id'  => $hosts_id
         ]
      ]);
      while ($data = $iterator->next()) {
         $values[$data['id']] = $data['name'];
      }
      return Dropdown::showFromArray('plugin_siem_services_id', $values, ['display' => false]);
   }

   public function showForm($ID, $options = []) {

      $this->initForm($ID, $options);
      $this->showFormHeader($options);

      echo '<tr><td>' .PluginSiemServiceTemplate::getTypeName(1). '</td><td>';
      echo Html::link($this->fields['name'], PluginSiemServiceTemplate::getFormURLWithID($this->fields['plugin_siem_servicetemplates_id']));
      echo '</td></tr>';
      echo '</table>';
      echo PluginSiemEvent::getListForHostOrService($ID, true);
      echo '<table class="tab_cadre_fixe">';

      $this->showFormButtons($options);

      return true;
   }

   public function checkNow()
   {
      global $DB;

      $event = new PluginSiemEvent();
      $service_table = self::getTable();
      $to_poll = $DB->request([
         'SELECT' => ['plugins_id', 'sensor'],
         'FROM' => $service_table,
         'LEFT JOIN' => [
            PluginSiemServiceTemplate::getTable() => [
               'FKEY' => [
                  $service_table => 'plugin_siem_servicetemplates_id',
                  PluginSiemServiceTemplate::getTable() => 'id',
               ]
            ]
         ],
         'WHERE' => [
            $service_table.'.id' => $this->getID(),
            'is_active' => 1
         ]
      ]);
      if (!count($to_poll)) {
         return false;
      }
      $poll_data = $to_poll->next();
      $plugin = new Plugin();
      $plugin->getFromDB($poll_data['plugins_id']);
      $results = Plugin::doOneHook($plugin->fields['directory'], 'poll_sensor', ['sensor' => $poll_data['sensor'], 'service_ids' => [$this->getID()]]);
      $eventdatas = [];
      $eventdatas[$plugin->fields['directory']][$poll_data['sensor']] = $results;

      // Create event from the results
      foreach ($eventdatas as $logger => $sensors) {
         foreach ($sensors as $sensor => $results) {
            if ($results !== null && is_array($results)) {
               foreach ($results as $service_id => $result) {
                  if ($result !== null && is_array($result)) {
                     $input = $result;
                     $input['plugin_siem_services_id'] = $service_id;
                     $event->add($input);
                  }
               }
            }
         }
      }
      return true;
   }
}