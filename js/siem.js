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

function refreshDashboard(ajax_url) {
    var form = $('#siem-dashboard-toolbar');
    var get_data = form.serialize();
    $.ajax({
        type: "GET",
        url: ajax_url,
        data: get_data,
        success: function(dashboard_html) {
            $('#siem-dashboard').replaceWith(dashboard_html);
            var url = window.location.href.split('?')[0];
            window.history.replaceState(null, null, url + "?" + get_data);
        }
    });
}

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