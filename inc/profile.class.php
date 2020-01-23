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
 * PluginSIEMProfile class. Adds plugin related rights tab to Profiles.
 * @since 1.0.0
 */
class PluginSiemProfile extends Profile
{
   static $rightname = "config";

   public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
   {
      return self::createTabEntry(__('SIEM Plugin', 'siem'));
   }

   static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
   {
      $siemprofile = new self();
      if ($item->fields['interface'] === 'central') {
         $siemprofile->showForm($item->getID());
      } else {
         return false;
      }
      return true;
   }

   /**
    * Print the SIEM plugin right form for the current profile
    *
    * @param int $profiles_id Current profile ID
    * @param bool $openform Open the form (true by default)
    * @param bool $closeform Close the form (true by default)
    * @return void|bool
    **/
   public function showForm($profiles_id = 0, $openform = true, $closeform = true)
   {
      global $CFG_GLPI;
      if (!self::canView()) {
         return false;
      }
      echo "<div class='spaced'>";
      $profile = new Profile();
      $profile->getFromDB($profiles_id);
      if ($openform && ($canedit = Session::haveRightsOr(self::$rightname, [CREATE, UPDATE, PURGE]))) {
         echo "<form method='post' action='" . $profile->getFormURL() . "'>";
      }
      $rights = [['itemtype' => 'PluginSiemHost',
         'label' => PluginSiemHost::getTypeName(Session::getPluralNumber()),
         'field' => 'plugin_siem_host'],
         ['itemtype' => 'PluginSiemService',
            'label' => PluginSiemService::getTypeName(Session::getPluralNumber()),
            'field' => 'plugin_siem_service'],
         ['itemtype' => 'PluginSiemServiceTemplate',
            'label' => PluginSiemServiceTemplate::getTypeName(Session::getPluralNumber()),
            'field' => 'plugin_siem_servicetemplate']];
      $matrix_options['title'] = __('SIEM Plugin', 'siem');
      $profile->displayRightsChoiceMatrix($rights, $matrix_options);
      if ($canedit
         && $closeform) {
         echo "<div class='center'>";
         echo Html::hidden('id', ['value' => $profiles_id]);
         echo Html::submit(_sx('button', 'Save'), ['name' => 'update']);
         echo "</div>\n";
         Html::closeForm();
      }
      echo '</div>';
   }
}