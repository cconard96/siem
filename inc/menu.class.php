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

/**
 * PluginSIEMMenu class. This class adds a menu which contains links to pages related to this plugin.
 * See /front/menu.php file for the menu content.
 */
class Menu extends CommonGLPI
{

   /**
    * Get name of this type by language of the user connected
    *
    * @param integer $nb number of elements
    * @return string name of this type
    */
   public static function getTypeName($nb = 0) {
      return __('SIEM plugin', 'siem');
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
      return Host::canView() || Service::canView() || ServiceTemplate::canView();
   }
}