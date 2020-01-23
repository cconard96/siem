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


class PluginSiemSensor
{

   /**
    * Gets an array of IPs or hostnames in order of preference when contacting the host.
    * @param int $hosts_id The host ID
    * @return array Array of IPs or hostnames in order of preference when contacting the host.
    */
   public function getPreferredAddresses($hosts_id)
   {
      $preferred = [];
      return $preferred;
   }

   protected static function poll($services_ids = [])
   {

   }

   final public static function invokePoll($service_ids = [])
   {
      return static::poll($service_ids);
   }
}