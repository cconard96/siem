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

use Calendar;
use CommonDBTM;
use CommonGLPI;
use Html;

/**
 * PluginSIEMHost class.
 * This represents a host that is able to be monitored through one or more PluginSIEMServices.
 *
 * @since 1.0.0
 */
class Host extends CommonDBTM
{
   use Monitored;

   static $rightname = 'plugin_siem_host';

   public static function getTypeName($nb = 0)
   {
      return _n('Host', 'Hosts', $nb, 'siem');
   }

   public function defineTabs($options = [])
   {
      $ong = [];
      $this->addDefaultFormTab($ong)
         ->addStandardTab(Service::class, $ong, $options);
      return $ong;
   }

   public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
   {
      if (!$withtemplate) {
         $nb = 0;
         switch ($item->getType()) {
            case __CLASS__ :
               return self::getTypeName();
            default:
               return self::createTabEntry('Event Management');
         }
      }
      return '';
   }

   public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
   {
      switch ($item->getType()) {
         case __CLASS__ :
            return self::showForm($item);
         default:
            self::showForm($item);
            break;
      }
      return true;
   }

   public static function getFormURLWithID($id = 0, $full = true)
   {
      global $DB;
      $iterator = $DB->request([
         'SELECT' => [
            'itemtype',
            'items_id'
         ],
         'FROM'   => self::getTable(),
         'WHERE'  => ['id' => $id]
      ]);
      $event_class = Event::class;
      if ($iterator->count()) {
         $item = $iterator->next();
         return $item['itemtype']::getFormURLWithID($item['items_id'], $full) . "&forcetab={$event_class}$1";
      }
      return '#';
   }

   public static function getSpecificValueToDisplay($field, $values, array $options = []) {
      global $DB;

      switch ($field) {
         case 'name':
            $iterator = $DB->request([
               'SELECT'    => ['name'],
               'FROM'      => $values['itemtype']::getTable(),
               'WHERE'     => ['id' => $values['items_id']]
            ]);
            if ($iterator->count()) {
               return $iterator->next()['name'];
            } else {
               return null;
            }
      }
      return parent::getSpecificValueToDisplay($field, $values, $options);
   }

   public function rawSearchOptions()
   {
      $service_table = Service::getTable();

      $tab = [];
      $tab[] = [
         'id' => 'common',
         'name' => __('Characteristics')
      ];
      $tab[] = [
         'id' => '2',
         'table' => self::getTable(),
         'field' => 'id',
         'name' => __('ID'),
         'massiveaction' => false,
         'datatype' => 'itemlink'
      ];
      $tab[] = [
         'id' => '3',
         'table' => self::getTable(),
         'field' => 'itemtype',
         'name' => __('Item type'),
         'datatype' => 'itemtypename'
      ];
      $tab[] = [
         'id' => '4',
         'table' => self::getTable(),
         'field' => 'items_id',
         'name' => __('Item ID'),
         'datatype' => 'number'
      ];
      $tab[] = [
         'id' => '7',
         'table' => $service_table,
         'field' => 'name',
         'linkfield' => 'plugin_siem_services_id_availability',
         'name' => __('Availability service'),
         'datatype' => 'itemlink'
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

   /**
    * Loads the host's availability service and then caches and returns it.
    * @return Service The loaded availability service or null if it could not be loaded.
    * @since 1.0.0
    */
   public function getAvailabilityService()
   {
      if (!$this->fields['plugin_siem_services_id_availability'] || $this->fields['plugin_siem_services_id_availability'] < 0) {
         return null;
      }
      // Load and cache availability service in case of multiple calls per page
      static $service = null;
      if ($service === null) {
         $service = new Service();
         if (!$service->getFromDB($this->fields['plugin_siem_services_id_availability'])) {
            return null;
         }
      }
      return $service;
   }

   public function checkNow()
   {
      return $this->getAvailabilityService()->checkNow();
   }

   public function getHostInfoDisplay()
   {
      global $DB, $CFG_GLPI;

      $twig_vars = [
         'host_info_bg'    => Service::getBackgroundColorClass($this->getStatus()),
         'toolbar_buttons' => [
            [
               'label' => __('Check now'),
               'action' => "window.pluginSiem.hostCheckNow({$this->getID()})",
            ],
            [
               'label' => __('Schedule downtime'),
               'action' => "hostScheduleDowntime({$this->getID()})",
            ],
            [
               'label' => sprintf(__('Add %s'), Service::getTypeName(1)),
               'action' => "window.pluginSiem.addHostService({$this->getID()})",
            ]
         ],
         'status'       => $this->getCurrentStatusName(),
         'host_stats'   => []
      ];

      if ($this->getAvailabilityService()) {
         $status_since_diff = Toolbox::getHumanReadableTimeDiff($this->getLastStatusChange());
         $last_check_diff = Toolbox::getHumanReadableTimeDiff($this->getLastStatusCheck());
         $twig_vars['host_stats'] = [
            __('Last status change') => ($status_since_diff ?? __('No change')),
            __('Last check') => ($last_check_diff ?? __('Not checked')),
            __('Flapping') => $this->isFlapping() ? __('Yes') : __('No')
         ];
      } else {
         $twig_vars['host_stats'] = [
            __('Host availability not monitored') => __('Set the availability service to monitor the host')
         ];
      }
      if (in_array($this->getStatus(), [Service::STATUS_CRITICAL, Service::STATUS_WARNING], true)) {
         $twig_vars['toolbar_buttons'][] = [
            'label' => sprintf(__('Acknowledge %s'), self::getTypeName(1)),
            'action' => "acknowledge({$this->getID()})",
         ];
      }
      if ($this->getAvailabilityService()) {
         $host_service = $this->getAvailabilityService();
         $calendar_name = __('Unspecified');
         if ($host_service->fields['calendars_id'] !== null) {
            $iterator = $DB->request([
               'SELECT' => ['name'],
               'FROM' => Calendar::getTable(),
               'WHERE' => ['id' => $host_service->fields['calendars_id']]
            ]);
            if ($iterator->count()) {
               $calendar_name = $iterator->next()['name'];
            }
         }
         $service_name = $host_service->fields['name'];
         $check_mode = Service::getCheckModeName($host_service->fields['check_mode']);
         $check_interval = $host_service->fields['check_interval'] ?? __('Unspecified');
         $notif_interval = $host_service->fields['notificationinterval'] ?? __('Unspecified');
         $twig_vars['service_stats'] = [
            [
               __('Name') => $service_name,
               __('Check mode') => $check_mode,
            ],
            [
               __('Check interval') => $check_interval,
               __('Notification interval') => $notif_interval,
            ],
            [
               __('Calendar') => $calendar_name,
               __('Flap detection') => $host_service->fields['use_flap_detection'] ? __('Yes') : __('No')
            ]
         ];
      } else {
         $form_url = self::getFormURL(true);
         $add_form = "<form method='POST' action='$form_url'>";
         $add_form .= Html::hidden('id', ['value' => $this->fields['id']]);
         $add_form .= '<fieldset>';
         $add_form .= '<legend>' . __('Service') . '</legend>';
         $add_form .= Service::getDropdownForHost($this->getID());
         $add_form .= Html::submit(__('Set availability service'), [
            'name' => 'set_host_service',
            'id' => '#btn-set-hostservice'
         ]);
         $add_form .= '</fieldset>';
         $add_form .= Html::closeForm(false);
         $twig_vars['add_availability_service_form'] = $add_form;
      }
      return Toolbox::getTwig()->render('elements/host_info.html.twig', $twig_vars);
   }

   /**
    * Form fields configuration and mapping.
    *
    * Array order will define fields display order.
    *
    * Missing fields from database will be automatically displayed.
    * If you want to avoid this;
    * @return array
    * @since 1.0.0
    *
    * @see getFormHiddenFields and/or @see getFormFieldsToDrop
    *
    */
   protected function getFormFields()
   {
      $fields = [
            'itemtype' => [
               'label' => __('Item type'),
               'type' => 'itemtype'
            ],
            'items_id' => [
               'label' => __('Item ID'),
               'type' => 'itemtype'
            ],
            'plugin_siem_services_id_availability' => [
               'label' => __('Availability service'),
               'type' => Service::class
            ],
            'is_reachable' => [
               'label' => __('Reachable'),
               'type' => 'yesno'
            ]
         ] + parent::getFormFields();
      return $fields;
   }

   public function dispatchSIEMHostEvent($eventName, $is_hard_status = true)
   {
      global $CONTAINER;
      if (!isset($CONTAINER) || !$CONTAINER->has(EventDispatcher::class)) {
         return;
      }
      $dispatcher = $CONTAINER->get(EventDispatcher::class);
      $dispatcher->dispatch($eventName, new PluginSIEMHostEvent($this, $is_hard_status));
   }

   public function getServices()
   {
      global $DB;
      static $services = null;
      if ($services === null) {
         $service_table = Service::getTable();
         $template_table = ServiceTemplate::getTable();
         $template_fk = ServiceTemplate::getForeignKeyField();

         $iterator = $DB->request([
            'SELECT' => [
               $service_table.'.*',
               $template_table.'.name',
               $template_table.'.plugins_id',
               $template_table.'.sensor'
            ],
            'FROM' => $service_table,
            'LEFT JOIN' => [
               $template_table => [
                  'FKEY' => [
                     $service_table => $template_fk,
                     $template_table => 'id'
                  ]
               ]
            ],
            'WHERE' => [
               self::getForeignKeyField() => $this->getID()
            ]
         ]);
         $services = [];
         while ($data = $iterator->next()) {
            $services[$data['id']] = $data;
         }
      }
      return $services;
   }

   /**
    * Sets the given service as the availability service for its host. If another availability service is already set, it is replaced.
    * @param integer $services_id The ID of the service that already belongs to the host.
    * @return boolean True if the availability service was successfully saved.
    */
   public function setAvailabilityService($services_id)
   {
      global $DB;
      $service = new Service();
      $match = $service->find([
         'id'  => $services_id
      ]);
      if (count($match) && reset($match)[self::getForeignKeyField()] === $this->getID()) {
         $DB->update(self::getTable(), ['plugin_siem_services_id_availability' => $services_id], ['id' => $this->getID()]);
         return true;
      }
      return false;
   }

   /**
    * Gets the asset that this host is tied to
    */
   public function getItemInfo()
   {
      $itemtype = $this->fields['itemtype'];
      $item = new $itemtype();
      $match = $item->find(['id' => $this->fields['items_id']]);
      return reset($match);
   }
}