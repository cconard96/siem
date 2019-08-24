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
 * SIEMServiceTemplate class.
 *
 * @since 1.0.0
 */
class PluginSiemServiceTemplate extends CommonDBTM {
    protected $twig_compat = true;


    static function getTypeName($nb = 0) {
        return _n('Service template', 'Service templates', $nb);
    }

    protected function getFormFields() {
        $fields = [
                'name' => [
                    'label'  => __('Name'),
                    'type'   => 'text'
                ],
                'comment' => [
                    'label'  => __('Comment'),
                    'type'   => 'textarea'
                ],
                'links_id' => [
                    'label'  => Link::getTypeName(1),
                    'type'   => 'Link'
                ],
                'priority' => [
                    'label'  => __('Priority'),
                    'type'   => 'select',
                    'values' => [
                        0  => CommonITILObject::getPriorityName(0),
                        -5 => CommonITILObject::getPriorityName(-5),
                        -4 => CommonITILObject::getPriorityName(-4),
                        -3 => CommonITILObject::getPriorityName(-3),
                        -2 => CommonITILObject::getPriorityName(-2),
                        -1 => CommonITILObject::getPriorityName(-1)
                    ],
                    //FIXME What is the purpose of requiring the following 2 keys?
                    'itemtype_name' => null,
                    'itemtype'      => null
                ],
                'calendars_id' => [
                    'label'  => __('Notification period'),
                    'type'   => 'Calendar',
                ],
                'notificationinterval' => [
                    'label'  => __('Notification interval'),
                    'type'   => 'number',
                ],
                'check_interval' => [
                    'label'  => __('Check interval'),
                    'type'   => 'number',
                ],
                'use_flap_detection' => [
                    'label'  => __('Enable flapping detection'),
                    'type'   => 'yesno',
                ],
                'check_mode' => [
                    'label'  => __('Enable flapping detection'),
                    'type'   => 'select',
                    'values' => [
                        PluginSiemService::CHECK_MODE_ACTIVE => __('Active'),
                        PluginSiemService::CHECK_MODE_PASSIVE => __('Passive'),
                        PluginSiemService::CHECK_MODE_HYBRID => __('Hybrid'),
                    ],
                    'itemtype_name' => null,
                    'itemtype' => null
                ],
                'is_stateless' => [
                    'label'  => __('Stateless'),
                    'type'   => 'yesno',
                ],
                'flap_threshold_low' => [
                    'label'  => __('Flapping lower threshold'),
                    'name'   => 'flap_threshold_low',
                    'type'   => 'number',
                ],
                'flap_threshold_high' => [
                    'label'  => __('Flapping upper threshold'),
                    'name'   => 'flap_threshold_high',
                    'type'   => 'number',
                ],
                'max_checks' => [
                    'label'  => __('Max checks'),
                    'name'   => 'max_checks',
                    'type'   => 'number',
                ],
                'logger' => [
                    //FIXME Why doesn't type 'Plugin' work here?
                    'label'  => __('Logger'),
                    'type'   => 'select',
                    'values' => [],
                    'itemtype_name' => null,
                    'itemtype' => null
                ],
                'sensor' => [
                    'label'  => __('Sensor'),
                    'type'   => 'select',
                    'values' => [],
                    'itemtype_name' => null,
                    'itemtype' => null
                ]
            ] + parent::getFormFields();
        return $fields;
    }
}