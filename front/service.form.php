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

use Glpi\Event;
use GlpiPlugin\SIEM\Service;

include('../../../inc/includes.php');
Html::header(Service::getTypeName(), $_SERVER['PHP_SELF'], 'management', Service::class);

$service = new Service();
if (!isset($_GET['id'])) {
   $_GET['id'] = -1;
}

if (isset($_POST['add'])) {
   $service->check(-1, CREATE, $_POST);
   if ($newID = $service->add($_POST)) {
      Event::log($newID, 'services', 4, 'management',
         sprintf(__('%1$s adds the item %2$s'), $_SESSION['glpiname'], $_POST['name']));

      if ($_SESSION['glpibackcreated']) {
         Html::redirect($service->getLinkURL());
      }
   }
   Html::back();

   // delete a computer
} else if (isset($_POST['delete'])) {
   $service->check($_POST['id'], DELETE);
   $ok = $service->delete($_POST);
   if ($ok) {
      Event::log($_POST['id'], 'services', 4, 'management',
         //TRANS: %s is the user login
         sprintf(__('%s deletes an item'), $_SESSION['glpiname']));
   }
   $service->redirectToList();

} else if (isset($_POST['restore'])) {
   $service->check($_POST['id'], DELETE);
   if ($service->restore($_POST)) {
      Event::log($_POST['id'], 'services', 4, 'management',
         //TRANS: %s is the user login
         sprintf(__('%s restores an item'), $_SESSION['glpiname']));
   }
   $service->redirectToList();

} else if (isset($_POST['purge'])) {
   $service->check($_POST['id'], PURGE);
   if ($service->delete($_POST, 1)) {
      Event::log($_POST['id'], 'services', 4, 'management',
         //TRANS: %s is the user login
         sprintf(__('%s purges an item'), $_SESSION['glpiname']));
   }
   $service->redirectToList();

   //update a computer
} else if (isset($_POST['update'])) {
   $service->check($_POST['id'], UPDATE);
   $service->update($_POST);
   Event::log($_POST['id'], 'services', 4, 'inventory',
      //TRANS: %s is the user login
      sprintf(__('%s updates an item'), $_SESSION['glpiname']));
   Html::back();
} else {
   $service->display(['id' => $_GET['id']]);
   Html::footer();
}