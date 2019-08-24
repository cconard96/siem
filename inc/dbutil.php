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
 * DB utilities for SIEM plugin.
 * Contains several methods not yet available in the core for interacting with the DB and tables.
 */
class PluginSIEMDBUtil {

    public static function dropTable($table)
    {
        global $DB;
        return $DB->query('DROP TABLE'.$DB->quoteName($table));
    }

    public static function dropTableOrDie($table, $message = '')
    {
        global $DB;
        $res = $DB->query('DROP TABLE'.$DB->quoteName($table));
        if (!$res) {
            //TRANS: %1$s is the description, %2$s is the query, %3$s is the error message
            $message = sprintf(
                __('%1$s - Error while dropping table %2$s - Error is %3$s'),
                $message,
                $table,
                $DB->error()
            );
            if (isCommandLine()) {
                throw new RuntimeException($message);
            } else {
                echo $message . "\n";
                die(1);
            }
        }
        return $res;
    }
}