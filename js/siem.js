/*
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

(function() {
   window.SIEMPlugin = function() {
      var self = this;
      this.ajax_root = CFG_GLPI.root_doc + "/plugins/siem/ajax/";
      this.dashboard = null;

      self.init = function(args) {
         this.ajax_root = CFG_GLPI.root_doc + "/plugins/siem/ajax/";
         if (args['dashboard'] !== undefined) {
            self.dashboard = args['dashboard'];
         }
      };

      var buildDashboardDeck = function(cards) {
         $(self.dashboard).empty();
         var content = "<div class='container-fluid content'>";
         content += "<h2 class='text-center'>Event Monitoring Dashboard</h2>";
         content += "<p class='text-center'>"+new Date()+"</p>";
         content += "<div class='siem-decks'>";
         $.each(cards, function(r_index, row) {
            content += "<div class='siem-deck card-deck'>";
            $.each(row, function(c_index, card) {
               var card_classes = ['siem-card', 'card', 'text-center', 'card-'+card.type];
               if (card.extra_card_classes !== undefined) {
                  card_classes.concat(card.extra_card_classes);
               }
               content += "<div class='"+card_classes.join(' ')+"'>";
               content += "<div class='card-header'><p class=''>"+card.title+"</p></div>";
               content += "<div class='card-body'>";
               content += buildCardBody(card);
               content += "</div></div>";
            });
            content += "</div>";
         });
         content += "</div></div>";
         $(content).appendTo($(self.dashboard));
      };

      var buildCardBody = function(card) {
         var content = '';
         if (card.type === 'counter') {
            return "<p>"+card.value+"</p>";
         } else if (card.type === 'table') {
            content += "<table class='w-100'><thead>";
            $.each(card.headers, function(i, header) {
               content += "<th>"+header+"</th>";
            });
            content += "</thead><tbody>";
            $.each(card.rows, function(i, row) {
               content += "<tr>";
               $.each(row, function(i2, cell) {
                  content += "<td class='"+(cell.class || '')+"'>" + cell.value + "</td>";
               });
               content += "</tr>";
            });
            content += "</tbody></table>";
         } else if (card.type === 'table-v') {
            content += "<table class='w-100'>";
            $.each(card.headers, function(i, header) {
               var cell = card.rows[i];
               content += "<tr class='"+(cell.class || '')+"'>";
               content += "<th class=''text-center>"+header+"</th>";
               content += "<td class='text-left'>"+cell.value+"</td>";
               content += "</tr>";
            });
            content += "</table>";
         } else {
            return "<p>"+card.value+"</p>";
         }
         return content;
      };

      self.refreshDashboard = function() {
         var form = $(self.dashboard+' .siem-toolbar');
         var get_data = form.serialize();
         $.ajax({
            type: "GET",
            url: self.ajax_root + 'siemdashboard.php',
            data: get_data,
            success: function (cards) {
               buildDashboardDeck(cards);
            }
         });
      };

      function toggleEventDetails(row) {
         var id = $(row).attr('id');
         var content_row = $("#" + id + "_content");

         if (typeof content_row !== typeof undefined) {
            var hidden_attr = content_row.attr('hidden');
            if (typeof hidden_attr !== typeof undefined) {
               content_row.removeAttr('hidden');
            } else {
               content_row.attr('hidden', 'hidden');
            }
         }
      }

      function serviceCheckNow(services_id) {

      }

      function hostScheduleDowntime(hosts_id) {

      }

      function serviceScheduleDowntime(services_id) {

      }

      function addService() {

      }
   };
})();