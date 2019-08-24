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
 * PluginSIEMHost class.
 * This represents a host that is able to be monitored through one or more PluginSIEMServices.
 *
 * @since 1.0.0
 */
class PluginSiemHost extends CommonDBTM {
    use PluginSiemMonitored;

    static $rightname                = 'plugin_siem_host';

    /** Host is up. */
    const STATUS_UP            = 0;
    /** Host should be reachable, but is down. Service alerts are suppressed. */
    const STATUS_DOWN          = 1;
    /** Host availability is not being monitored. */
    const STATUS_UNKNOWN       = 2;
    /** Host is not reachable because an upstream device is down. */
    const STATUS_UNREACHABLE   = 3;

    static function getTypeName($nb = 0)
    {
        return _n('Host', 'Hosts', $nb);
    }

    function defineTabs($options = []) {
        $ong = [];
        $this->addDefaultFormTab($ong)
            ->addStandardTab('PluginSiemService', $ong, $options);
        return $ong;
    }

    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$withtemplate) {
            $nb = 0;
            switch ($item->getType()) {
                case 'PluginSiemHost' :
                    return self::getTypeName();
                default:
                    return self::createTabEntry('Event Management');
            }
        }
        return '';
    }

    static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        switch ($item->getType()) {
            case 'PluginSiemHost' :
                return self::showForm($item);
            default:
                self::showForm($item);
                break;
        }
        return true;
    }

    public static function getStatusName($status)
    {
        switch ($status) {
            case PluginSiemService::STATUS_OK:
            case PluginSiemService::STATUS_WARNING:
                return __('Up');
            case PluginSiemService::STATUS_CRITICAL:
                return __('Down');
            default:
                return __('Unknown');
        }
    }

    function rawSearchOptions()
    {
        $tab = [];
        $tab[] = [
            'id'                 => 'common',
            'name'               => __('Characteristics')
        ];
        $tab[] = [
            'id'                 => '2',
            'table'              => $this->getTable(),
            'field'              => 'id',
            'name'               => __('ID'),
            'massiveaction'      => false,
            'datatype'           => 'number'
        ];
        $tab[] = [
            'id'                 => '3',
            'table'              => $this->getTable(),
            'field'              => 'itemtype',
            'name'               => __('Item type'),
            'datatype'           => 'itemtypename'
        ];
        $tab[] = [
            'id'                 => '4',
            'table'              => $this->getTable(),
            'field'              => 'items_id',
            'name'               => __('Item ID'),
            'datatype'           => 'number'
        ];
        $tab[] = [
            'id'                 => '7',
            'table'              => 'glpi_plugin_siem_services',
            'field'              => 'name',
            'linkfield'          => 'plugin_siem_services_id_availability',
            'name'               => __('Availability service'),
            'datatype'           => 'itemlink'
        ];
        $tab[] = [
            'id'                 => '19',
            'table'              => $this->getTable(),
            'field'              => 'date_mod',
            'name'               => __('Last update'),
            'datatype'           => 'datetime',
            'massiveaction'      => false
        ];
        $tab[] = [
            'id'                 => '121',
            'table'              => $this->getTable(),
            'field'              => 'date_creation',
            'name'               => __('Creation date'),
            'datatype'           => 'datetime',
            'massiveaction'      => false
        ];
        //TODO Add availability service search options
        return $tab;
    }

    public function getBackgroundColorClass()
    {
        switch ($this->getStatus()) {
            case self::STATUS_DOWN:
            case self::STATUS_UNREACHABLE:
                return 'bg-danger';
            case self::STATUS_UP:
                return 'bg-success';
            case self::STATUS_UNKNOWN:
                return 'bg-warning';
        }
        return '';
    }

    /**
     * Loads the host's availability service and then caches and returns it.
     * @return PluginSiemService The loaded availability service or null if it could not be loaded.
     *@since 1.0.0
     */
    public function getAvailabilityService()
    {
        if (!$this->fields['plugin_siem_services_id_availability']) {
            return null;
        }
        // Load and cache availability service in case of multiple calls per page
        static $service = null;
        if ($service == null) {
            $service = new PluginSiemService();
            if (!$service->getFromDB($this->fields['siemservices_id_availability'])) {
                return null;
            }
        }
        return $service;
    }

    public function getHostInfoDisplay()
    {
        global $DB;

        $host_info_bg = $this->getBackgroundColorClass();
        $status = self::getStatusName($this->getStatus());
        if ($this->getAvailabilityService()) {
            $status_since_diff = PluginSIEMToolbox::getHumanReadableTimeDiff($this->getLastStatusChange());
            $last_check_diff = PluginSIEMToolbox::getHumanReadableTimeDiff($this->getLastStatusCheck());
            $host_stats = [
                __('Last status change')   => (is_null($status_since_diff) ? __('No change') : $status_since_diff),
                __('Last check')           => (is_null($last_check_diff) ? __('Not checked') : $last_check_diff),
                __('Flapping')             => $this->isFlapping() ? __('Yes') : __('No')
            ];
        } else {
            $host_stats = [
                __('Host availability not monitored') => __('Set the availability service to monitor the host')
            ];
        }
        $toolbar_buttons = [
            [
                'label'  => __('Check now'),
                'action' => "hostCheckNow({$this->getID()})",
            ],
            [
                'label'  => __('Schedule downtime'),
                'action' => "hostScheduleDowntime({$this->getID()})",
            ],
            [
                'label'  => sprintf(__('Add %s'), PluginSiemService::getTypeName(1)),
                'action' => "addService({$this->getID()})",
            ]
        ];
        if (in_array($this->getStatus(), [self::STATUS_DOWN, self::STATUS_UNREACHABLE])) {
            $toolbar_buttons[] = [
                'label'  => sprintf(__('Acknowledge %s'), self::getTypeName(1)),
                'action' => "acknowledge({$this->getID()})",
            ];
        }
        $btn_classes = 'btn btn-primary mx-1';
        $toolbar = "<div id='host-actions-toolbar'><div class='btn-toolbar'>";
        foreach ($toolbar_buttons as $button) {
            $toolbar .= "<button type='button' class='{$btn_classes}' onclick='{$button['action']}'>{$button['label']}</button>";
        }
        $toolbar .= "</div></div>";
        $out = $toolbar;
        $out .= "<div id='host-info' class='w-25 float-right inline {$host_info_bg}'>";
        $out .= "<table class='text-center w-100'><thead><tr>";
        $out .= "<th colspan='2'><h3>{$status}</h3></th>";
        $out .= "</tr></thead><tbody>";
        foreach ($host_stats as $label => $value) {
            $out .= "<tr><td><p style='font-size: 1.5em; margin: 0px'>{$label}</p><p style='font-size: 1.25em; margin: 0px'>{$value}</p></td></tr>";
        }
        $out .= '</tbody></table></div>';
        $out .= "<div id='host-service-info' class='inline float-left w-75'>";
        if ($this->getAvailabilityService()) {
            $host_service = $this->getAvailabilityService();
            $calendar_name = __('Unspecified');
            if (!is_null($host_service->fields['calendars_id'])) {
                $iterator = $DB->request([
                    'SELECT' => ['name'],
                    'FROM'   => Calendar::getTable(),
                    'WHERE'  => ['id' => $host_service->fields['calendars_id']]
                ]);
                if ($iterator->count()) {
                    $calendar_name = $iterator->next()['name'];
                }
            }
            $service_name = $host_service->fields['name'];
            $check_mode = PluginSiemService::getCheckModeName($host_service->fields['check_mode']);
            $check_interval = !is_null($host_service->fields['check_interval']) ?
                $host_service->fields['check_interval'] : __('Unspecified');
            $notif_interval = !is_null($host_service->fields['notificationinterval']) ?
                $host_service->fields['notificationinterval'] : __('Unspecified');
            $service_stats = [
                [
                    __('Name')                    => $service_name,
                    __('Check mode')              => $check_mode,
                ],
                [
                    __('Check interval')          => $check_interval,
                    __('Notification interval')   => $notif_interval,
                ],
                [
                    __('Calendar')                => $calendar_name,
                    __('Flap detection')          => $host_service->fields['use_flap_detection'] ? __('Yes') : __('No')
                ]
            ];
            $out .= "<h3>".__('Availability service info') . "</h3>";
            $out .= "<table class='text-center w-100'><tbody>";
            foreach ($service_stats as $statrow) {
                $out .= "<tr>";
                foreach ($statrow as $label => $value) {
                    $out .= "<td><p style='font-size: 1.5em; margin: 0px'>{$label}</p><p style='font-size: 1.25em; margin: 0px'>{$value}</p></td>";
                }
                $out .= "</tr>";
            }
            $out .= '</tbody></table>';

        } else {
            $out .= "<form>";
            $out .= "<label for='service'>" . __('Service') . "</label>";
            $out .= Plugin::dropdown([
                'name' => 'service',
                'display' => false
            ]);
            $out .= Html::closeForm(false);
        }
        $out .= "</div>";
        return $out;
    }

    /**
     * Form fields configuration and mapping.
     *
     * Array order will define fields display order.
     *
     * Missing fields from database will be automatically displayed.
     * If you want to avoid this;
     * @see getFormHiddenFields and/or @see getFormFieldsToDrop
     *
     * @since 1.0.0
     *
     * @return array
     */
    protected function getFormFields() {
        $fields = [
                'itemtype'  => [
                    'label'  => __('Item type'),
                    'type'   => 'itemtype'
                ],
                'items_id'  => [
                    'label'  => __('Item ID'),
                    'type'   => 'itemtype'
                ],
                'plugin_siem_services_id_availability' => [
                    'label'  => __('Availability service'),
                    'type'   => 'PluginSiemService'
                ],
                'is_reachable' => [
                    'label'  => __('Reachable'),
                    'type'   => 'yesno'
                ]
            ] + parent::getFormFields();
        return $fields;
    }

    public function dispatchSIEMHostEvent($eventName, $is_hard_status = true) {
        global $CONTAINER;
        if (!isset($CONTAINER) || !$CONTAINER->has(EventDispatcher::class)) {
            return;
        }
        $dispatcher = $CONTAINER->get(EventDispatcher::class);
        $dispatcher->dispatch($eventName, new PluginSIEMHostEvent($this, $is_hard_status));
    }
    public function getServices() {
        global $DB;
        static $services = null;
        if ($services === null) {
            $servicetable = PluginSiemService::getTable();
            $templatetable = PluginSiemServiceTemplate::getTable();
            $iterator = $DB->request([
                'FROM'      => $servicetable,
                'LEFT JOIN' => [
                    $templatetable => [
                        'FKEY'   => [
                            $servicetable  => 'plugin_siem_servicetemplates_id',
                            $templatetable => 'id'
                        ]
                    ]
                ],
                'WHERE'     => [
                    'siemhosts_id'  => $this->getID()
                ]
            ]);
            while ($data = $iterator->next()) {
                $services[$data['id']] = $data;
            }
        }
        return $services;
    }
}