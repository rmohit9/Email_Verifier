/************************************
 * BACKEND TEAM:
 * GET /api/admin/users
 *
 * Response:
 * [
 *   {
 *     id,
 *     name,
 *     email,
 *     status   // ACTIVE | SUSPENDED
 *   }
 * ]
 ************************************/
async function loadAdmins() {
  try {
    const res = await fetch("/api/admin/users", {
      credentials: "include",
    });

    const admins = await res.json();
    const table = document.getElementById("adminsTable");

    table.innerHTML = "";

    admins.forEach((admin) => {
      table.innerHTML += `
        <tr class="border-t">
          <td class="p-4 font-semibold">${admin.name}</td>
          <td class="p-4">${admin.email}</td>
          <td class="p-4">
            <span class="px-3 py-1 rounded-full text-xs font-bold
              ${
                admin.status === "ACTIVE"
                  ? "bg-emerald-100 text-emerald-700"
                  : "bg-amber-100 text-amber-700"
              }">
              ${admin.status}
            </span>
          </td>
          <td class="p-4 text-right">
            <button
              onclick="deleteAdmin('${admin.id}')"
              class="text-red-600 font-semibold hover:underline">
              Delete
            </button>
          </td>
        </tr>
      `;
    });
  } catch (err) {
    console.error("Failed to load admins", err);
  }
}

/************************************
 * BACKEND TEAM:
 * POST /api/admin/users
 ************************************/
function openAddAdminModal() {
  alert("Add Admin modal (backend will handle creation)");
}

/************************************
 * BACKEND TEAM:
 * DELETE /api/admin/users/:id
 ************************************/
async function deleteAdmin(id) {
  if (!confirm("Are you sure you want to delete this admin?")) return;

  await fetch(`/api/admin/users/${id}`, {
    method: "DELETE",
    credentials: "include",
  });

  loadAdmins();
}

loadAdmins();
